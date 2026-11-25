#!/usr/bin/env bash
set -euo pipefail
compose_file=$1
enabled=$2
ids=()
uuid_v4='^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[89aAbB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$'
if [[ "$enabled" == true ]]; then
    # Read registered identities from the disposable fixture DB only. The HTTP
    # probe deliberately does not make a client authentication or mTLS claim.
    for nf_type in SMF AMF; do
        id=""
        for attempt in {1..24}; do
            if id=$(timeout -k 2s 5s docker compose -f "$compose_file" exec -T --interactive=false db mongo --quiet free5gc \
                --eval "var p=db.NfProfile.findOne({nfType:'$nf_type',nfStatus:'REGISTERED'}); if(p) print(p.nfInstanceId)") && [[ "$id" =~ $uuid_v4 ]]; then
                break
            fi
            id=""
            sleep 2
        done
        [[ "$id" =~ $uuid_v4 ]] || { echo "No registered $nf_type fixture" >&2; exit 1; }
        ids+=("$id")
    done
fi
docker compose -f "$compose_file" exec -T --interactive=false it bash /root/test/test-it-oauth.sh "$enabled" "${ids[@]}"
