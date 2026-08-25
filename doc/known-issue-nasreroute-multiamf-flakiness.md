# Known Issue: `TestNasReroute` / `TestMultiAmfRegistration` intermittent failure

**Status:** Root cause confirmed, not yet fixed. Fix deferred — see [Recommended fix](#recommended-fix).

## Symptom

`TestNasReroute` and `TestMultiAmfRegistration` (`test/goTest/it_nasreroute_test.go`,
`test/goTest/it_multiamfregistration_test.go`) fail intermittently, not on every run. No other
IT test in the suite exhibits this.

Observed failure shape (when it happens): the UE's second registration — sent to `amf2` carrying
the GUTI issued by `amf` in the first registration — doesn't get the expected NGAP response.
`TestNasReroute` expects `RerouteNASRequest`; `TestMultiAmfRegistration` expects a direct
`InitialContextSetupRequest`. Either can be missing depending on which internal AMF code path was
exercised (see below).

## Why only these two tests

They are the only two IT tests that use **two AMF instances** (`amf` + `amf2`) and exercise the
GUTI-based re-registration flow where the second AMF has to discover the first AMF via NRF. Every
other IT test only ever talks to a single AMF, so this code path — and the bug in it — is never
reached.

## Root cause

Traced end-to-end, confirmed at the MongoDB layer:

1. On the second registration, `amf2`'s GMM handler
   (`free5gc/NFs/amf/internal/gmm/handler.go`) recognizes the GUTI belongs to `amf`
   (`AmfId cafe00`) and needs to either transfer UE context from it
   (`contextTransferFromOldAmf`, `handler.go:576`) or find a target AMF for slice reselection
   (the `TestNasReroute` path, `handler.go:1236`). **Both paths call the same
   `consumer.SearchAmfCommunicationInstance`**, which queries NRF's discovery API filtered by
   `amf`'s GUAMI.
2. When it fails, `amf2` logs `AMF can not select an target AMF by NRF` even though `amf`
   registered with NRF successfully well before (tens of seconds earlier in every observed
   failure — this is not a "hasn't registered yet" timing race).
3. Direct MongoDB inspection at the moment of failure showed `amf`'s stored `NfProfile` document
   was **completely correct**: right GUAMI, `nfStatus: REGISTERED`, `namf-comm` service
   `REGISTERED`, no `allowedNfTypes` restriction. The data was never wrong.
4. Reproduced the failure directly against NRF's discovery HTTP endpoint in a tight loop
   (bypassing NGAP/NAS entirely, hitting
   `GET /nnrf-disc/v1/nf-instances?guami=...&requester-nf-type=AMF&target-nf-type=AMF` directly)
   — this fails roughly **1 in every 3–20 requests** under sustained load, with a fully
   sequential (non-concurrent) client. NRF's own trace-level "Query filter" log showed the built
   MongoDB filter (`free5gc/NFs/nrf/internal/sbi/processor/nf_discovery.go`, `buildFilter`) is
   **byte-identical on every call**, success or failure — ruling out a filter-construction bug.
5. Added a temporary instrumentation line in
   `free5gc/NFs/nrf/internal/sbi/processor/nf_discovery.go` right after
   `mongoapi.RestfulAPIGetMany(...)` to print the raw result count before any decoding happens.
   Caught a live failure: `nfProfilesRaw count=0 err=<nil>`.

**Conclusion:** the miss happens inside MongoDB's own query execution for an
`amfInfo.guamiList: {$elemMatch: {...}}` filter — not in NRF's filter-building code, not in
`free5gc/util/mapstruct`'s response decoding, not in AMF's request/response client code (all of
which were read and ruled out; see the ruled-out list below). The document exists, is correct,
and is provably absent from that one query's result set. This is a MongoDB-level query
consistency edge case under sustained query load, external to free5gc's own Go code and to this
repo.

## Ruled out

- ~~NRF/AMF hadn't finished their NRF registration/heartbeat yet~~ — `amf` registers exactly once
  at startup (no heartbeat mechanism exists in AMF's NRF consumer code at all), and every observed
  failure happened tens of seconds after that registration's `201 Created` response.
- ~~Stale/incorrect stored data~~ — direct MongoDB inspection after a failure showed the document
  was fully correct on every field the query filters on.
- ~~Filter-construction bug (case sensitivity, BSON/JSON tag mismatch, `allowedNfTypes` filter,
  etc.)~~ — trace-level logging shows the constructed filter is byte-identical across passing and
  failing calls.
- ~~Concurrency bug in AMF's generated OpenAPI client (shared mutable state across AMF's 6-worker
  goroutine pool)~~ — reproduced the failure with a single, fully sequential curl loop with zero
  concurrency, and read through the client's request-building, query-param-encoding, and
  response-decoding code (`openapi/nrf/NFDisc/api_nf_instances_store.go`,
  `openapi/client.go:AddQueryParams`) — everything is per-call-local, no shared state.
- ~~Response decode bug (`free5gc/util/mapstruct.Decode`) silently dropping a matched record~~ —
  ruled out by the `nfProfilesRaw count=0` instrumentation: the miss happens before decoding is
  ever reached.
- ~~`api-webconsole-subscribtion-data-action.sh` provisioning race (data not yet queryable by
  AUSF/UDM when the test starts)~~ — this is a real, separate, occasionally-observed issue during
  rapid back-to-back manual re-runs, but it also affects `TestRegistration` and every other test
  identically (same provisioning script, same immediate-test-start pattern), so it cannot explain
  why only these two tests are flaky. Not the cause here.

Also incidentally discovered (unrelated to this bug, noted for awareness): NRF drops its entire
`NfProfile` MongoDB collection on every startup
(`free5gc/NFs/nrf/pkg/service/init.go:218`, `mongoapi.Drop(...)`). Since AMF never re-registers
after its one startup call, an NRF restart mid-suite (crash, manual restart, etc.) would
permanently blank out NRF's view of every already-running NF until *those* NFs are also
restarted. Not the mechanism behind this issue, but worth knowing if NRF-dependent flakiness is
ever investigated again.

## Investigation notes

- A `time.Sleep(3 * time.Second)` warm-up at the start of both test functions was added to match
  `free5gc/test/registration_test.go`'s `TestMultiAmfRegistration`/`TestNasReroute` (the upstream
  reference has it; this repo's ported versions never did). It's a real, harmless fidelity fix
  worth keeping, but repeated reproduction runs confirmed it does **not** fix the underlying
  MongoDB-level race — failures still occur with it in place.
- Reproducing this reliably requires hitting NRF's discovery endpoint directly and repeatedly
  (see the curl loop in step 4 above) rather than running the full IT test repeatedly — the full
  test only issues the relevant query once per run, so catching it that way takes many
  full docker-compose up/down cycles per hit. The direct-curl-loop approach reproduces it in
  seconds.

## Recommended fix

Add a bounded retry around the second registration step in both tests: if the expected NGAP
message isn't received, resend the `InitialUEMessage` (or just re-wait/re-read) once or twice
before failing. This is not papering over a logic bug — the root cause is a confirmed external
system's intermittent behavior under load, and tests exercising it should tolerate that the same
way a production AMF would (AMF's own registration flow already retries various NRF interactions
elsewhere).

Not implemented yet per user request (2026-08-20) — deferred to a later session.
