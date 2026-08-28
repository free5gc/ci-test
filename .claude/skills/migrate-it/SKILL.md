---
name: migrate-it
description: Use when migrating a test from free5gc/test/ to test/goTest/ as an IT (Integration Test). Input is a test function name (e.g. TestRegistration). Covers file placement, naming conventions, const substitution, auth data, SUCI buffer, test script creation, and webconsole JSON.
---

# migrate-it

## Overview

將 `free5gc/test/` 中的 test function migrate 到 `test/goTest/`，使其以 IT（Integration Test）方式執行。IT test 不操作 MongoDB，改用 webconsole API 預先注入 UE 資料，並透過實際網路介面連接 AMF。

---

## 執行步驟

### Step 1 — 讀取來源 test

到 `free5gc/test/` 找目標 test function（例如 `TestRegistration` 在 `registration_test.go`）。注意：
- source package 是 `test_test`，IT package 是 `test`
- source 使用 `test.ConnectToAmf()`，IT 使用 `connectToAmf()`（來自 `conn_amf.go`）
- source 呼叫 `test.InsertUeToMongoDB()`，IT **不呼叫**（由 webconsole API 預先注入）

### Step 2 — 建立 IT test 檔

檔名命名規則：`it_<testname_lowercase>_test.go`，例如 `it_registration_test.go`。
放置於 `test/goTest/`，package 宣告為 `package test`。

**Import 規則（來自 it_registration_test.go 的參考）：**
```go
import (
    "testing"
    "time"

    "github.com/free5gc/nas"
    "github.com/free5gc/nas/nasMessage"
    "github.com/free5gc/nas/nasType"
    "github.com/free5gc/nas/security"
    "github.com/free5gc/ngap"
    "github.com/free5gc/ngap/ngapType"
    "github.com/free5gc/openapi/models"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)
```
不要 import `TestGenAuthData`（test 資料改用 webconsole JSON）。
NAS 函式直接呼叫（`GetRegistrationRequest` 等），無需加套件前綴，因為 `nas.go` 在同一 package。
NGAP 函式同理（`GetNGSetupRequest`、`GetInitialUEMessage` 等）。

### Step 3 — 替換 UE 連線方式

| 來源 (free5gc/test) | IT 目標 (test/goTest) |
|---|---|
| `test.ConnectToAmf(ranN2Ipv4Addr, amfN2Ipv4Addr, ...)` | `connectToAmf(AMF_IP, IT_IP, AMF_PORT, IT_N2_PORT)` |
| `test.InsertUeToMongoDB(t, ue, servingPlmnId)` | **刪除**（不需要） |
| 硬寫 IP 字串 | 改用 `const.go` 中的常數 |

### Step 4 — 替換 NGAP 函式呼叫

Source 使用 `test.GetXxx(...)` 或 `ngapTestpacket.BuildXxx(...)`，IT 使用同名函式但加在 `test/goTest/ngap.go` 中。

**命名規則（ngap.go）：**
- 內部 builder：`buildXxx`（小寫 b，package private）
- 對外 encoder：`GetXxx`（大寫 G，public）
- 每個 `GetXxx` 呼叫對應的 `buildXxx`，並用 `ngap.Encoder()` 包裝

若 source 呼叫的 NGAP 函式在 `test/goTest/ngap.go` 中不存在，需從 `free5gc/test/ngapTestpacket/build.go` 複製對應 `BuildXxx`，然後：
1. 重新命名 `BuildXxx` → `buildXxx`（b 小寫）
2. 新增 `GetXxx` wrapper：
   ```go
   func GetXxx(args...) ([]byte, error) {
       return ngap.Encoder(buildXxx(args...))
   }
   ```
3. **替換所有 hardcode 常數為 `const.go` 的值（見 Step 5）**

### Step 5 — const.go 常數替換規則

在 `ngap.go` 的 `buildXxx` 函式中，以下 hardcode 字串必須換成 `const.go` 常數：

| 原始值 | 替換為 |
|---|---|
| `"\x02\xf8\x39"` (PLMN) | `aper.OctetString(PLMN_OCT)` |
| `[]byte{0x45,0x46,0x47}` 或其他 GNB ID bytes | `aper.OctetString(IT_GNB_ID)` |
| `"\x01"` (SST) | `aper.OctetString(SST_OCT)` |
| `"\xfe\xdc\xba"` 或其他 SD | `aper.OctetString(SD_OCT)` |
| `"\x00\x00\x01"` (TAC) | `aper.OctetString("\x00\x00\x01")`（保持不變，TAC 無專用常數） |

**NRCellIdentity 規則（重要）：**
`NRCellIdentity` 是 36-bit 欄位，bytes 長度必須是 5（不是 3）：
```go
// 正確
NRCellIdentity.Value = aper.BitString{
    Bytes:     []byte{0x00, 0x00, 0x00, 0x00, 0x10},
    BitLength: 36,
}
// 錯誤 — 使用 IT_GNB_ID (3 bytes) 會 panic
NRCellIdentity.Value = aper.BitString{
    Bytes:     aper.OctetString(IT_GNB_ID), // 只有 3 bytes，BitLength=36 需要 5 bytes
    BitLength: 36,
}
```

**package 頂層 PLMN 變數（ngap.go 已存在）：**
```go
var (
    PLMN = ngapType.PLMNIdentity{
        Value: aper.OctetString(PLMN_OCT),
    }
)
```

### Step 6 — 替換 NAS 函式呼叫

Source 使用 `nasTestpacket.GetXxx(...)`，IT 使用同名函式（在 `test/goTest/nas.go` 中）。

若 `nas.go` 缺少某個函式，從 `free5gc/test/nasTestpacket/NasPdu.go` 複製進來，**不改函式簽名與邏輯**，只調整 package（去掉 `nasTestpacket.` 前綴的呼叫）。

### Step 7 — 替換 UE 資料

**禁止**使用 `MilenageTestSet19` 或其他 test set 資料。改用 webconsole JSON 的值。

| 欄位 | 來源 |
|---|---|
| IMSI | `const.go` 的 `UE_IMSI` |
| K (permanentKey) | webconsole JSON 的 `permanentKeyValue` |
| OPC | webconsole JSON 的 `opcValue` |
| SQN | webconsole JSON 的 `sequenceNumber`（必須與 `GetAuthSubscription` 中的 `Sqn` 完全一致） |
| SUCI buffer | 根據 IMSI 計算（見下方） |

**GetAuthSubscription 呼叫：**
```go
ue.AuthenticationSubs = GetAuthSubscription(UE_K, UE_OPC, "")
```
K、OPC、SQN 均定義在 `const.go`（`UE_K`、`UE_OPC`、`UE_SQN`），**不可在 test 或 ranUeContext.go 中直接硬寫字串**。`ranUeContext.go` 的 auth subscription 函式使用 `UE_SQN`，與 webconsole JSON 的 `sequenceNumber` 一致。**不要修改 GetAuthSubscription 的函式簽名。**

**SUCI buffer 計算（for `imsi-208930000000001`）：**
```go
mobileIdentity5GS := nasType.MobileIdentity5GS{
    Len:    13,
    Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10},
}
```
SUCI 格式：`0x01`（SUCI type） + PLMN bytes（`\x02\xf8\x39`） + routing indicator（`\x00\x00`） + protection scheme（`\x00`） + home network public key ID（`\x00`） + MSIN（BCD encoded, padded to 5 bytes）

MSIN `0000000001` → BCD: `00 00 00 00 10`（最後 nibble pad `f`，但若偶數則為 `10`）。

若 migrate 的 test 使用不同 IMSI，需重新計算 SUCI buffer。

**Serving Network Name** 格式固定：
```go
"5G:mnc093.mcc208.3gppnetwork.org"
```
（根據 PLMN `20893`：mcc=208, mnc=093）

### Step 8 — 建立 webconsole JSON

路徑：`test/json/webconsole-subscription-data-it.json`（若已存在則確認 IMSI 正確）。

若有不同 IMSI 的 test，需建立新的 JSON 檔，命名為 `webconsole-subscription-data-<testname>.json`。

Key 欄位：
- `ueId`：`imsi-<IMSI>`
- `plmnID`：`20893`
- `permanentKeyValue`：K
- `opcValue`：OPC
- `sequenceNumber`：SQN（必須與 `GetAuthSubscription` 中一致）
- NSSAI SD：`"010203"`（對應 `SD = "010203"` in `const.go`）

### Step 9 — 建立測試入口 shell script

路徑：`test/test-it-<testname_lowercase>.sh`，參考 `test-it-registration.sh` 結構：

```bash
#!/bin/bash
echo "Running IT <TestName> test"

./api-webconsole-subscribtion-data-action.sh post json/webconsole-subscription-data-it.json
if [ $? -ne 0 ]; then
    echo "Failed to post subscription data"
    exit 1
fi

cd goTest
go test -v -vet=off -run <TestName>
go_test_exit_code=$?
cd ..

./api-webconsole-subscribtion-data-action.sh delete json/webconsole-subscription-data-it.json
if [ $? -ne 0 ]; then
    echo "Failed to delete subscription data"
    exit 1
fi

exit $go_test_exit_code
```

若測試使用不同 IMSI，需使用對應的 `webconsole-subscription-data-<testname>.json`。

---

## 已知特殊模式（續）

### EAP-AKA' 認證（`TestEAPAKAPrimeAuthentication`）

EAP-AKA' 與 5G-AKA 的差異：

| 項目 | 5G-AKA | EAP-AKA' |
|---|---|---|
| Auth subscription 函式 | `GetAuthSubscription(UE_K, UE_OPC, "")` | `GetEAPAKAPrimeAuthSubscriptionIT(UE_K, UE_OPC)` |
| Authentication Response | `GetAuthenticationResponse(resStat, "")` | `GetAuthenticationResponse(nil, base64.StdEncoding.EncodeToString(resEAPMessage))` |
| 計算 response | `ue.DeriveRESstarAndSetKey(...)` | `ue.DeriveResEAPMessageAndSetKey(...)` |
| EAP message 取得 | — | `nasPdu.AuthenticationRequest.GetEAPMessage()` |
| webconsole JSON | `authenticationMethod: "5G_AKA"` | `authenticationMethod: "EAP_AKA_PRIME"` |

**`GetEAPAKAPrimeAuthSubscriptionIT`**（在 `ranUeContext.go`）是專為 IT 建立的版本，使用 IT SQN `"000000000023"`，與原本 `GetEAPAKAPrimeAuthSubscription` 硬寫 `TestGenAuthData.MilenageTestSet19.SQN` 不同。

**不同 IMSI / auth method 的 test** 需建立對應的 webconsole JSON（例如 `webconsole-subscription-data-it-eapakaprime.json`），shell script 對應使用該 JSON。

**不包含 PDU session 流程的 test** 在 Registration Complete + UE Configuration Update Command 後直接結束（`time.Sleep(100ms)` + return），不需要 UPF 連線。

**需要 import `"encoding/base64"`** 才能使用 `base64.StdEncoding.EncodeToString`。

---

### SQN 遞增（多 round authentication）

Test 中若需在第二次 Authentication 前遞增 SQN（例如 `TestGUTIRegistration`），必須使用 `fmt.Sprintf("%012x", sqn)` 格式化，**不可用 `strconv.FormatUint`**，否則遺失 leading zero 導致 SQN 長度不足 6 bytes：

```go
// 正確
sqn, _ := strconv.ParseUint(ue.AuthenticationSubs.SequenceNumber.Sqn, 16, 48)
sqn++
ue.AuthenticationSubs.SequenceNumber.Sqn = fmt.Sprintf("%012x", sqn)

// 錯誤 — FormatUint 不補零，"000000000023"+1 → "24"（1 byte），網路端報錯
ue.AuthenticationSubs.SequenceNumber.Sqn = strconv.FormatUint(sqn, 16)
```

需同時 import `"fmt"` 和 `"strconv"`。

---

## 常見錯誤

| 錯誤 | 原因 | 修正 |
|---|---|---|
| `panic: index out of range [4] with length 3` in aper | NRCellIdentity.Bytes 只有 3 bytes 但 BitLength=36 需要 5 bytes | 改用 5-byte 值 `[]byte{0x00,0x00,0x00,0x00,0x10}` |
| Authentication Reject (0x58) | K 或 OPC 不符 webconsole JSON | 對照 JSON 的 `permanentKeyValue` / `opcValue` |
| NAS MAC 驗證失敗 | SQN 不符 | 確認 `GetAuthSubscription` 中的 `Sqn` 與 webconsole JSON `sequenceNumber` 完全一致 |
| compile error: undefined `TestGenAuthData` | 誤 import 了 TestGenAuthData | 移除 import，K/OPC 直接傳字串給 `GetAuthSubscription` |
| compile error: undefined `test.ConnectToAmf` | 用了 source 的連線函式 | 改用 `connectToAmf()` |

---

## IT test 與 free5gc reference test 差異表

| 項目 | free5gc/test (reference) | test/goTest (IT) |
|---|---|---|
| Package | `test_test` | `test` |
| MongoDB 注入 | `test.InsertUeToMongoDB()` | 不需要（webconsole API） |
| AMF 連線 | `test.ConnectToAmf(ranN2Ipv4Addr, ...)` | `connectToAmf(AMF_IP, IT_IP, AMF_PORT, IT_N2_PORT)` |
| NGAP 函式 | `test.GetXxx()` / `ngapTestpacket.BuildXxx()` | `GetXxx()`（同 package） |
| NAS 函式 | `nasTestpacket.GetXxx()` | `GetXxx()`（同 package） |
| K / OPC / SQN | TestSet hardcode | webconsole JSON 對應值 |
| IMSI | test 自訂 | `UE_IMSI` from `const.go` |
| SD | `"fedcba"` 等 | `SD = "010203"` from `const.go` |
| Test 入口 | 直接 `go test` | shell script（post → test → delete） |

---

## 已知特殊模式

### `recvUeConfigUpdateCmd` 類型的 helper 函式

Source test 中若有 helper function（例如 `recvUeConfigUpdateCmd`）包裝了一段 assert/read 邏輯，**IT test 中一律 inline 展開**，並加上 `// equivalent to <helperName> in reference test` 的註解，說明對應的來源。

```go
// receive UE Configuration Update Command (equivalent to recvUeConfigUpdateCmd in reference test)
n, err = n2Conn.Read(recvMsg)
assert.Nil(t, err)
ngapPdu, err = ngap.Decoder(recvMsg[:n])
assert.Nil(t, err)
assert.Equal(t, ngapPdu.Present, ngapType.NGAPPDUPresentInitiatingMessage, "Not NGAPPDUPresentInitiatingMessage")
assert.Equal(t, ngapPdu.InitiatingMessage.ProcedureCode.Value, ngapType.ProcedureCodeDownlinkNASTransport, "Not ProcedureCodeDownlinkNASTransport")
```

### Hardcoded 5G-GUTI（Deregistration Request）

Deregistration Request 使用 5G-GUTI 作為 mobile identity，GUTI 是 AMF 在 Registration 完成後分配的。**初次 migrate 時沿用 source test 的 hardcoded 值**，並加上以下處理：

1. 加 comment 說明需驗證：
   ```go
   // 5G-GUTI is assigned by AMF during registration; verify buffer matches AMF assignment if test fails
   ```
2. 加 `fmt.Printf` 方便手動跑時比對：
   ```go
   fmt.Printf("[DEBUG] Using 5G-GUTI for Deregistration: %v\n", mobileIdentity5GS.Buffer)
   ```
3. 使用者手動跑一次，若 GUTI 不符則回來更新 Buffer 值。

---

## 遇到未知情況必須確認

**在 migrate 過程中，若遇到此 skill 未涵蓋的情況，必須先向使用者確認，不可自行假設並實作。**

需要確認的情況包括但不限於：
- source test 使用了 `test/goTest/ngap.go` 或 `nas.go` 中不存在的函式，且其行為不確定
- source test 的 UE 資料結構（IMSI、PLMN、NSSAI）與現有 `const.go` / webconsole JSON 不同，不確定應新增常數或新增 JSON
- source test 有特殊的 assert 邏輯或 test 流程（例如多 UE、handover、multi-path）
- source test 依賴目前 IT 環境不存在的 NF 或外部服務
- 任何在此 skill 各步驟中沒有明確指示的判斷

**確認方式：** 列出遇到的不確定情況，詢問使用者的意圖，等待回覆後再繼續實作。不可先實作再說明。

---

## 更新此 skill

每次使用者糾正 migrate 錯誤後，立即更新此 SKILL.md 對應章節。更新要點：
- 新增或修正「常見錯誤」表格
- 若有新的常數替換規則，加入 Step 5 的表格
- 若函式簽名限制有新規定，加入對應 Step
