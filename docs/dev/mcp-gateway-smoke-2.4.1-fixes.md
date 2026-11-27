# `raijin mcp` sau bản sửa `46613ae`: smoke test, chỗ dễ lỗi, error message cho model yếu

Ngày 2026-11-27. CLI `cli/target/release/raijin` và jar `build/libs/raijin.jar` build từ `46613ae` (HEAD `a5db710` chỉ thêm `lefthook.yml`; không có file nguồn nào mới hơn artifact). Burp Suite Pro 2026.10.1 headless, target `/Users/datnguyen/Projects/raijin`. Bản trước: `mcp-gateway-smoke-2.4.1.md`.

Cách test:
- 396 call JSON-RPC thô qua stdio: 151 khi Burp tắt, 245 khi Burp chạy, 11 trên era 2026-07-28. Gồm 163 case cũ của lần 2.4.1 cộng 185 case mới.
- Chạy lại đúng 48 `retry` mà server trả về, để kiểm lời hứa "retry là call đã sửa, chắc chắn đúng".
- 4 call qua client thật (Claude Code `guide`/`run`) và 4 `curl` vào `/api/v1`.

Mình **không** chạy DeepSeek thật. Các thói quen "model yếu" bên dưới lấy từ những dạng call đã thấy ở hai lần trước, cộng các dạng phổ biến của client kiểu OpenAI.

Tác dụng phụ:
- Archive của project `main` có thêm khoảng 16 exchange tới `127.0.0.1:1` (port đóng); `history_list` total từ 34 lên 50.
- Đã xoá `.raijin/exports/20261127T021518Z` và 2 file spill của lần này. 2 file spill của lần 2.4.1 vẫn giữ nguyên.
- Scope và findings không đổi. Burp đã tắt (`burp_down` graceful).

## Tóm tắt

Phần lớn mục của 2.4.1 đã sửa đúng khi chạy với Burp thật:
- Có 170 kết quả lỗi, tất cả đều là JSON có `code` và `retryable`.
- `retry` gói `burp_up` chạy được end-to-end: `burp_up` mất 7.1 s, rồi call gốc chạy luôn.
- 30 `example` chọn tay (read-only, chạy local) đều chạy được.

Vấn đề còn lại tập trung ở chỗ server **đoán sai mà vẫn tự tin**:
- 5/48 `retry` không chạy được, cả 5 đều do một luật so khớp substring.
- Gõ sai `project` thì nhận được `retry` khởi động một Burp mới.
- 102/198 `example` vẫn là placeholder, model copy vào là ra "thành công" với dữ liệu rác.

Lớp lỗi lớn nhất vẫn là `unknown_parameter` (40/170). Gần như tất cả các case này server đã biết chắc tên đúng, nhưng vẫn bắt model tốn thêm một lượt gửi lại.

## Kiểm lại các mục của 2.4.1 với Burp thật

| Call (eval 2.4.1) | Bây giờ |
|---|---|
| Burp tắt: `{"do":"scope.chek","url":"https://a.b"}` | ok: `unknown_tool`, `did_you_mean:["scope.check","scope"]`, không gợi ý `burp_up` |
| Burp tắt: `{"do":"util.hash",...}` | ok: `retry` = `{"batch":[{"do":"burp_up"},<call>],"bail":true}`. Chạy thử thì Burp lên và call chạy |
| Burp tắt: `scope.remove`, `burp.shutdown` | ok: không có `retry` |
| `batch` với `bail:"true"` | ok: dừng ở step 1 |
| `http_send_request headers:["X-A: 1"]` | ok: header lên wire. `["no colon here"]` → `invalid_type`, không gửi |
| `util.base64_decode data:"!!!"` | ok: `invalid_arguments`, `param:"data"`, nêu ký tự `'!'` |
| `turbo_run.status run_id:"nope"` | ok: `not_found`, `see` → `turbo_run.list`. Nhưng câu lỗi không có dấu chấm (P2-12) |
| `sitemap.query count:1` | ok: `retry` với `max_results` |
| `util.hash input:"x"` | ok: `retry` với `data` (chưa tự áp dụng, P2-5) |
| `history_list project:"nope"` | ok: `invalid_enum`, `allowed:["main"]`, `retry` |
| `http_send_request` không tham số | ok: `example` có `url` |
| `guide util.hash` | **một phần**: schema đã thu hẹp, nhưng vẫn kèm description của cả `util` và enum gộp (P2-10) |
| `run {"do":"guide"}`, `{"do":"run"}`, `{"do":5}`, `steps`, step dạng string | ok |
| `http_send_request` tới port đóng | ok: `no_response`, `time_request_sent: null` |
| Tool API 415/400, `Host: evil.com` | ok: `code` + `retryable`; 403 |
| `resources/read` với URI không có | legacy → `-32002`. Era 2026-07-28 → `-32602`; đúng spec, vì rmcp 3.11 `model.rs:684` map `resource_not_found` theo SEP-2164 |

Số liệu từ audit tự động (`audit.py` trên 334 kết quả):

| Chỉ số | Giá trị |
|---|---|
| Lỗi thiếu `code`/`retryable` | 0 |
| Lỗi không phải JSON | 0 |
| `code` xuất hiện | `unknown_parameter` 40, `unknown_tool` 25, `missing_parameter` 22, `invalid_type` 21, `invalid_arguments` 19, `not_found` 14, `invalid_enum` 14, `burp_not_running` 10, `unknown_action` 5, `unknown_topic` 4, `project_not_running` 2, `tool_failed` 2, `missing_action` 1, `out_of_range` 1 |
| Cỡ lỗi | median 265 B, p90 730 B, max 1155 B |
| `retry` chạy lại được | 43/48. 5 cái hỏng đều do P1-1 |
| `see` | luôn là string (114/114) |

## Chỗ dễ lỗi, cần sửa

Nguyên tắc khi xếp loại: dễ dãi (cho call đi qua, kể cả call destructive) là chủ ý của tool pentest, nên không tính là bug. Bug là khi server **đoán sai**, **làm khác ý định mà không báo**, hoặc **báo thành công cho thứ đã fail**.

### P1: gợi ý sai nhưng có vẻ chắc chắn

**1. `retry` trỏ sang `ai` hoặc `log` vì so khớp substring.**

| Call | Kết quả |
|---|---|
| `{"do":"raijin.history_list","limit":1}` (Burp tắt và Burp chạy) | `did_you_mean:["ai"]`, `retry:{"do":"ai","limit":1}` |
| `{"do":"mcp__raijin__history_list","limit":1}` | như trên |
| `{"do":"email"}`, `{"do":"details","id":1}` | `retry:{"do":"ai"...}` |
| `{"do":"catalog"}` | `retry:{"do":"log"}` |
| `{"do":"raijin.proxy_history","count":1}` | `did_you_mean:["proxy_history","ai"]`: đúng tên nhưng không có `retry` |

- Hậu quả: chạy lại cả 5 `retry` này đều nhận `missing_action`. Một `retry` trỏ tới tool nhóm mà thiếu action thì không bao giờ là call hoàn chỉnh. Model thật hay gắn tiền tố server (`mcp__raijin__...`, `raijin.`), vì client hiển thị tool dưới dạng `mcp__raijin__run`.
- Nguyên nhân:
  - `cli/crates/raijin-cli/src/util.rs:87` và `ToolArgs.kt:25` (`closest`) coi `normed.contains(w) || w.contains(normed)` là "gần". `ai` và `log` là substring của rất nhiều chữ.
  - `mcp/server.rs:1142` (và nhánh tương ứng phía Kotlin) gắn `retry` hễ còn đúng một gợi ý.
  - Danh sách ứng viên phía CLI không có tool native (`history_*`, `burp_*`), nên `raijin.history_list` không bao giờ khớp `history_list`.
- Sửa:
  - Bỏ các tiền tố đã biết trước khi tra: `mcp__raijin__`, `raijin.`, `raijin:`, `raijin/`, `functions.`. Ghi `notes` khi bỏ.
  - Chỉ coi substring là gần khi tên ngắn hơn có ít nhất 4 ký tự và phủ được ít nhất 60% tên cần tìm.
  - Đưa tool native vào danh sách ứng viên.
  - Chỉ gắn `retry` khi gợi ý duy nhất có khoảng cách nhỏ **và** call sau khi sửa qua được `ToolArgs.fits`. Tool nhóm thì `retry` phải có action.

**2. Gõ sai `project` thì `retry` khởi động một Burp mới.**
- `{"do":"burp.version","project":"MAIN"}` và `{"project":"nope"}` → `project_not_running` kèm `retry:{"batch":[{"do":"burp_up","project":"MAIN"},...]}`. Model yếu chạy theo là có thêm một Burp nữa với file project mới (`MAIN.burp`, `nope.burp`).
- Phía history của CLI làm đúng: `history_list project:"MAIN"` → `invalid_enum`, `allowed:["main"]`.
- Vị trí: `mcp/server.rs:785`.
- Sửa: tra project trong `.burp` của target và các instance đang biết.
  - Khớp không phân biệt hoa/thường → dùng luôn, ghi `notes`.
  - Không có project nào như vậy → `invalid_enum` kèm `allowed` và `retry` với project đúng.
  - Chỉ trả `retry` có `burp_up` khi project đó có thật nhưng đang tắt.

**3. `example` dạng placeholder: model copy y nguyên là lặp lại lỗi, hoặc nhận "thành công" với dữ liệu rác.**

Audit catalog: 102/198 `example` có giá trị kiểu `"<url>"`, `"<run_id>"`, hoặc `[{}]`. Lỗi của các action này trả lại đúng placeholder đó.

| Call (copy từ `example`) | Kết quả |
|---|---|
| `util.jwt_decode token:"<token>"` | lỗi, và `example` trong lỗi lại là `"<token>"` (vòng lặp) |
| `analyze.response response:"<response>"` | **ok**, `status_code: 0` |
| `persistence.get key:"<key>"` | ok, `found:false` |
| `websocket.history_search pattern:"<pattern>"` | ok, 0 match |
| `analyze.diff item1:"<item1>"` | `"URL is invalid."`: sai hướng, đúng lỗi đã sửa cho `analyze.request` |
| `util.decompress data:"<data>"` | `tool_failed`, `retryable:false`, `Illegal base64 character 3c` |
| `http_send_request_chain steps:[{}]`, `http_send_requests_parallel requests:[{}]` | `isError:false`, lỗi nằm trong từng step |
| `probe.access_control requests:[{}],identities:[{}]` | `tool_failed`, `retryable:false` |

- Nguồn: `ToolExamples.kt` chỉ chọn tay 59 entry; phần còn lại rơi về placeholder của `ToolArgs.example`.
- Sửa:
  - Chọn tay `example` cho mọi action đọc hoặc ghi mà model hay gọi, khoảng 40 cái tiếp theo: `scope.include`, `findings.add`, `turbo_run.start`, `util.jwt_decode` (một JWT mẫu thật), `analyze.*`, `collaborator.*`.
  - Với id phải lấy từ call khác: bỏ hẳn tham số đó khỏi `example`, và trỏ `see` tới call liệt kê.
  - Không bao giờ sinh `[{}]`.
- Phát hiện echo placeholder:
  - Value đúng bằng `"<" + tên param + ">"` (đúng dạng mà generator sinh ra), hoặc có dạng `<... from ...>`.
  - Với tham số id, url hoặc token: trả `code: placeholder_value` kèm `param`, `see`.
  - Với tham số text tự do (`data`, `body`, `message`): chỉ thêm `notes`, vẫn gửi, vì pentest có thể cố tình gửi chuỗi `<...>`.

**4. Chạy hỏng hết mà vẫn báo thành công.**
- `batch` không có `bail` mà có step fail → `isError:false`, và top-level không có tóm tắt. Model yếu chỉ đọc `isError` và field đầu tiên.
- `http_send_request_chain` có 2 step đều không có response → `isError:false`, `completed_steps:1`.
- Sửa:
  - Batch: thêm `failed_steps:[2]` ở top-level.
  - Chain và parallel: nếu không step nào thành công thì `isError:true` kèm `error` tóm tắt (`2 of 2 steps got no response`).

### P2: model yếu vấp

**5. Synonym chỉ đưa `retry`, không tự áp dụng.**
- 40/170 lỗi là `unknown_parameter`. Phần lớn là synonym server đã biết chắc: `count`→`limit`, `limit`→`count`, `query`/`q`/`regex`→`pattern`, `input`/`text`/`string`/`value`→`data`, `uri`→`url`, `request`↔`raw_request`, `offset`→`start_index`. Mỗi case tốn một lượt gửi lại.
- Lượt gửi lại là chỗ DeepSeek hay viết lại call và tạo lỗi mới, thay vì copy y nguyên `retry`.
- Vị trí: `mcp/args.rs:385`, `ToolArgs.kt:328`.
- Sửa: khi map là duy nhất và tham số đích chưa có thì **áp dụng luôn** và ghi `notes: ["read 'limit' as 'count'"]`, giống cách `"20"` đang được ép thành `20`. Chỉ trả lỗi khi mơ hồ, ví dụ gửi cả `count` lẫn `limit`.

**6. `regex` nằm trong nhóm synonym của `pattern`.**
- Ở nhiều API khác, `regex: true` là cờ boolean ("dùng regex").
- `history_search query:"(" regex:true` → cả hai bị hiểu là `pattern`, và lỗi không có `retry`.
- Vị trí: `mcp/args.rs:331`, `ToolArgs.kt:282`.
- Sửa: synonym chỉ áp dụng khi kiểu giá trị hợp với tham số đích (string → `pattern`). Nếu `regex` là boolean thì bỏ, kèm `notes: "pattern is always a regex here"`.

**7. Tên tham số chưa được chuẩn hoá, bảng synonym còn thiếu.**
- Phía Rust, `history_list maxResults:1` → không gợi ý gì. Phía Kotlin thì `includeRequest` vẫn ra `include_request`.
- `Limit` và `limit*` (copy dấu `*` từ `usage`) đều ra `retry`, nhưng lẽ ra nên tự áp dụng luôn.
- `events.get limit:5` → không gợi ý, vì `max_events` chưa có trong nhóm count.
- Sửa:
  - Chuẩn hoá trước khi tra: trim, lowercase, camelCase → snake_case, bỏ `*`.
  - Quét catalog, thêm các tên `max_*` mang nghĩa đếm (`max_events`, ...) vào nhóm count. Không thêm `max_response_length`, `max_body`, `max_depth`.

**8. Các dạng `do` chưa nhận ra.**
- `"history_list()"`, `"history_list(limit=1)"`, `"history_list(limit: integer)"` và `"history/list"` → `unknown_tool` không kèm gợi ý. Giờ `usage` viết dạng `history_list(limit: ...)` nên model càng dễ copy dạng này.
- `{"function":"history_list"}`, `{"tool_name":...}`, `{"action":"history_list"}`, và shape OpenAI `{"type":"function","function":{"name":"history_list","arguments":"{\"limit\":1}"}}` → `run needs "do"`, không kèm gợi ý.
- Sửa:
  - Bỏ hậu tố `(...)` (ghi `notes`); nếu bên trong có `k=v` thì đọc thành tham số.
  - Coi `/` là dấu phân cách.
  - Nhận `function`, `tool_name`, `function.name` + `function.arguments` làm `do`.
  - Thiếu `do` mà `action` là tên một tool thì dùng `action` làm `do`.

**9. Rust và Kotlin dễ dãi không đều nhau.**
- `include_request:1` được Kotlin nhận, còn `dedupe:1` và `bail:1` thì Rust từ chối.
- Enum không phân biệt hoa/thường (`sha256`, `http2`), nhưng `project:"MAIN"` thì có phân biệt.
- `history_show ref:1` (hoặc `"1"`) khi target chỉ có project `main` → lỗi. Đây là case chắc chắn: nên đọc thành `main:1`, ghi `notes`.
- Sửa: một bảng ép kiểu chung, sinh vào catalog giống `param_synonyms`.

**10. `guide tool.action` còn nhiễu, và có chỗ sai.**
- `guide util.hash` (2.4 KB) vẫn trả description của cả `util` (12 action, ghi theo dạng `{"action":...}`).
- `usage`/`inputSchema` của `hash` liệt kê `algorithm: ...|"GZIP"|"DEFLATE"|"BROTLI"` (enum gộp với `compress`). Gửi `util.hash algorithm:"GZIP"` thì nhận `invalid_enum`. Description của `data` cũng gộp mô tả của mọi action.
- `guide scope.remove` có bốn ký pháp trong một response: `{"do":"scope.remove"}`, `scope.remove(list*...)`, `{"action":"check"}`, `scope(action=list)`.
- Sửa:
  - Lấy enum và description theo schema của member trước khi gộp.
  - Khi đã thu hẹp về một action thì chỉ giữ dòng của action đó.
  - Viết lại description theo dạng `tool.action`.

**11. Lỗi handler còn sai `code`, sai `param`, hoặc sai hướng.**

| Call | Hiện tại | Nên là |
|---|---|---|
| `util.decompress data:"<data>"` | `tool_failed`, `retryable:false`, `character 3c` | như `base64_decode`: `invalid_arguments`, `param:"data"`, `'<' at 0` |
| `probe.access_control` thiếu tham số | `tool_failed`, `retryable:false` | `missing_parameter`, `retryable:true` |
| `proxy_annotate id:99999999` | `not_found`, `see` → `guide proxy_annotate` | `see` → `{"do":"proxy_history"}` |
| `http_send_request follow_redirects:true` | `invalid_arguments`, không có `allowed` | đọc `true`→`always`, `false`→`never` (ghi `notes`), hoặc `invalid_enum` kèm `allowed` |
| `proxy_history_search search_in:"headers"` | câu lỗi ghi `Allowed: all, both, ...` nhưng `allowed` thiếu `all` (`ProxyTools.kt:128` nhận `all` làm alias) | hai chỗ phải khớp nhau |
| `scope.remove index:999` | `param:"list"`, `got:"include"` (`enrich` đoán sai), câu lỗi dùng `scope(action=list)` | `out_of_range`, `param:"index"`, `see:{"do":"scope.list"}` |

**12. Còn hai mẫu câu lỗi không có dấu chấm cuối**, trái với lời hứa của CHANGELOG ("`error` always ends as a sentence"):
- `turbo_run.status: not found (run_id "nope")` (gặp ở cả `turbo_run.results`);
- `Parameter 'timeout_ms' must be an integer (got "5s")`.

Test hiện tại chưa duyệt hết các mẫu câu.

**13. Lựa chọn trên wire mà không báo.** Không cần chặn gì, chỉ thêm `notes`:
- `raw_request` không có `use_tls` → chọn TLS, kể cả khi `Host: 127.0.0.1:1` (`request_secure:true`). Retry `request`→`raw_request` cũng gửi sang `https://`.
- Gửi cả `url` lẫn `raw_request` → `raw_request` thắng mà không báo.
- `body:{"a":1}` → được serialize thành JSON mà không báo. `headers:{"X-A":1}` → số bị ép sang string mà không báo.

**14. Warning nằm rải rác ở nhiều field:**
- `notes` (38 lần), `warnings` (32, ở history, dạng object), `scope_warning` (14), `headers_warning` (1);
- clamp lúc thì là `length_clamped_to`, lúc thì là `notes: "count 1000000 is outside 0..1000; used 1000"`.

Model yếu chỉ đọc một chỗ. Nên gom mọi thứ không fatal vào `notes: [string]`, và giữ field cũ thêm một release để tương thích.

### P3

**15. `do` và `action` xung đột** (`{"do":"scope.list","action":"remove",...}` chạy `scope.remove`) là chủ ý, giữ nguyên. Chỉ nên thêm `notes: "ran scope.remove ('action' overrides 'do')"` để model biết thứ gì đã chạy. Vị trí: `transport/ToolApi.kt:140`.

**16. Input của `guide`:**
- `guide {"do":"util.hash"}` → `unknown_parameter`. `guide` đã nhận `name` và `tool`, nên nhận thêm `do`.
- `guide {"topic":"util.hash","data":"x"}` → lỗi. Nên bỏ field thừa và ghi `notes`.
- Topic dạng câu (`"how do I send a request"`) → không có gợi ý. Có thể khớp từ khoá với description để ra `http_send_request`.
- `retry` của lỗi guide là `{"topic":"history"}`, tức tham số của `guide`, trong khi mọi `retry` khác là tham số của `run`. Model yếu sẽ gửi nó vào `run`. Nên ghi rõ, ví dụ `see: "guide {\"topic\":\"history\"}"`, và bỏ `retry`.

**17. Example chọn tay:**
- Doc comment của `ToolExamples.kt` ghi "read-only", nhưng thực tế:
  - `proxy_annotate` ghi comment vào item 1;
  - `log.message` ghi vào log;
  - `send_to_tool.repeater` mở tab Repeater;
  - `http_send_request`, `http_send_raw_bytes`, `recon.fingerprint` gửi traffic thật tới example.com.

  Giữ các example này cũng được; chỉ cần sửa lại câu mô tả trong comment.
- `events.get` trả 134 KB và bị spill. Example nên có `max_events: 20`.

**18. Batch:**
- `batch:{...}` (một object) → lỗi; nên bọc thành mảng và ghi `notes`.
- Khi step fail có `retry`, top-level không có `retry` cho cả batch đã sửa, nên model phải tự ghép lại.

## Error message để DeepSeek và model yếu dùng được

12 nguyên tắc của bản 2.4.1 vẫn đúng, và phần envelope (có `code`/`retryable`, là JSON, có `usage` và `example`) đã đạt. Lần test này cho thêm 9 bài học, xếp theo số lỗi mà mỗi bài ngăn được:

1. **Chắc chắn thì sửa luôn, đừng trả lỗi.** Mỗi lượt sửa-gửi-lại là một cơ hội để model yếu viết lại call và sai chỗ khác. "Chắc chắn" nghĩa là map duy nhất từ bảng (synonym, chuẩn hoá hoa/thường/camel, ép kiểu), không phải edit distance. Áp dụng xong thì ghi `notes`. Lỗi chỉ dành cho case mơ hồ.
2. **Cái gì đã trả trong `retry` thì phải chạy được.** Kiểm `retry` bằng chính `ToolArgs.fits` và tra tên chính xác trước khi trả. Tool nhóm thì phải có action. Không bao giờ để `retry` tạo state mà caller không xin (Burp mới, project mới). Eval chạy lại mọi `retry` (lần này 43/48) nên thành test cố định.
3. **Không chắc thì im.** `did_you_mean` rỗng kèm `see:"guide {}"` tốt hơn một gợi ý sai: model yếu chọn gợi ý đầu tiên. Không so khớp substring với tên ngắn.
4. **`example` không bao giờ là placeholder.** Giá trị phải lấy từ call khác thì nói trong `see` (`{"do":"turbo_run.list"}`), đừng ghi `"<run_id>"`. Server nhận lại đúng placeholder của chính nó thì gọi tên lỗi đó ra (`placeholder_value`).
5. **Thất bại phải nổi lên top-level.** `isError:false` với lỗi nằm trong `steps[1].result` coi như không có lỗi đối với model yếu. Batch cần `failed_steps`; chain/parallel fail toàn bộ thì phải là `isError:true`.
6. **Một chỗ duy nhất cho "đã chạy nhưng có chuyện"**: `notes: [string]`. Đừng để `scope_warning`, `headers_warning`, `warnings`, `*_clamped_to` cạnh nhau; model không biết field nào quan trọng.
7. **`see` nên là call chạy được, không phải string chứa JSON escape.** `"see":"run {\"do\":\"turbo_run.list\"}"` buộc model tự parse. Nên dùng `"see":{"do":"turbo_run.list"}`. Riêng guide thì dùng `{"guide":{"topic":"..."}}`, hoặc giữ string và thêm `see_call`.
8. **Câu lỗi ngắn, quan trọng nhất đặt trước.** Hiện median là 265 B, nhưng lỗi của tool lớn lên tới 700–1100 B, chủ yếu vì `usage` của `http_send_request` (khoảng 600 B) hoặc danh sách enum dài (`turbo_docs.get_example`). Với `unknown_parameter` và `invalid_enum`, chỉ nên đưa tối đa 5 tên gần nhất cộng `see`. Model local context nhỏ sẽ cắt phần đuôi.
9. **Một ký pháp ở mọi nơi**, kể cả description: `{"do":"scope.remove",...}` để gọi, `scope.remove(list*: ...)` để mô tả. Bỏ hẳn `{"action":...}` và `scope(action=list)`.

Khuôn mẫu đề xuất:

```json
{"error":"<tool.action>: <cái gì sai>. <làm gì tiếp>.",
 "code":"<một trong tập đã biết>", "param":"<tên>", "got":<giá trị>,
 "retry":{"do":"...", ...},            // chỉ khi đã kiểm là chạy được
 "see":{"do":"<call liệt kê/cần gọi trước>"},
 "allowed":[...],                       // tối đa ~20, kèm "see" nếu bị cắt
 "retryable":true}
```

### Trước / sau

| Hiện tại | Đề xuất |
|---|---|
| `{"do":"mcp__raijin__history_list","limit":1}` → `retry:{"do":"ai","limit":1}` | chạy `history_list`, `notes:["read 'mcp__raijin__history_list' as history_list"]` |
| `{"do":"burp.version","project":"MAIN"}` → `retry` bật Burp `MAIN` | chạy trên `main`, `notes:["matched project \"MAIN\" to \"main\""]` |
| `{"do":"proxy_history","limit":2}` → `unknown_parameter` + `retry` | chạy với `count:2`, `notes:["read 'limit' as 'count'"]` |
| `util.jwt_decode token:"<token>"` → lỗi, `example` vẫn là `"<token>"` | `{"error":"util.jwt_decode: 'token' is the placeholder from the example; pass a real JWT (header.payload.signature).","code":"placeholder_value","param":"token","example":{"do":"util.jwt_decode","token":"eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opsbCGfG_HACGpVUMN_a9IV7pAx_Zmeo"},"retryable":true}` |
| chain 2/2 step không có response → `isError:false` | `isError:true`, `"error":"http_send_request_chain: 2 of 2 steps got no response (127.0.0.1:1 refused).","code":"no_response"` |
| batch không `bail`, step 2 fail → không có tóm tắt | `"failed_steps":[2]` ở top-level |
| `"see":"run {\"do\":\"turbo_run.list\"}"` | `"see":{"do":"turbo_run.list"}` |
| `guide util.hash` → `algorithm: ...\|"GZIP"\|"DEFLATE"\|"BROTLI"` | `util.hash(data*: string, algorithm*: "MD5"\|"SHA_1"\|"SHA_256"\|"SHA_384"\|"SHA_512")` |
| `turbo_run.status: not found (run_id "nope")` | `turbo_run.status: no run "nope". List runs with turbo_run.list.` |

## Test nên thêm

- **Rust, `util::suggest` và `resolve_call`:**
  - `email`, `catalog`, `details` → không gợi ý `ai`/`log`;
  - `raijin.history_list`, `mcp__raijin__proxy_history` → resolve được;
  - một `retry` cho tool nhóm luôn có action.
- **Kotlin, `ToolArgs.closest`:** các case như trên. Thêm property test: mọi `retry` mà `enrich` sinh ra đều qua được `fits` và `ToolNames.resolve` chính xác.
- **Rust, `server.rs:785`:** `project` không có file `.burp` → không có `retry` chứa `burp_up`.
- **Catalog:** đếm số `example` có `<...>` hoặc `[{}]`, và giữ con số này giảm dần (hiện 102/198).
- **Kotlin:** gom mọi mẫu câu lỗi, assert kết thúc bằng `.`/`?`/`!` (hiện có 2 mẫu fail).
- **Eval weak-model** (chạy lại harness; ghi `ok` khi đạt):

| Call | Hiện tại |
|---|---|
| `{"do":"mcp__raijin__history_list","limit":1}` | `retry` → `ai` |
| `{"do":"email"}` | `retry` → `ai` |
| `{"do":"burp.version","project":"MAIN"}` | `retry` bật Burp mới |
| `{"do":"proxy_history","limit":2}` | lỗi + `retry` (chưa tự áp dụng) |
| `{"do":"history_list","maxResults":1}` | không có gợi ý |
| `{"do":"history_search","query":"(","regex":true}` | hai synonym trùng đích, không có `retry` |
| `{"do":"history_list()"}` | `unknown_tool`, không có gợi ý |
| `{"type":"function","function":{"name":"history_list","arguments":"{}"}}` | `run needs "do"` |
| `{"do":"analyze.response","response":"<response>"}` | ok với dữ liệu rác |
| `{"do":"http_send_request_chain","steps":[{"url":"http://127.0.0.1:1/a"},{"url":"http://127.0.0.1:1/b"}]}` | `isError:false` |
| `{"do":"util.hash","data":"x","algorithm":"GZIP"}` sau `guide util.hash` | `usage` liệt kê GZIP |
| `{"do":"history_show","ref":1}` (một project) | `invalid_type` |
| Burp tắt: `{"do":"util.hash","data":"x","algorithm":"MD5"}` → chạy `retry` | ok |
| `{"do":"http_send_request","url":"http://127.0.0.1:1/","headers":["X-A: 1"]}` | ok |
| `{"batch":[{"do":"history_show"},{"do":"burp_status"}],"bail":"true"}` | ok |

## Chưa kiểm

- DeepSeek, Qwen, GLM thật (mọi kết luận về model yếu ở trên là suy ra từ dạng call, chưa chạy model);
- picker `/skill` của omp;
- nhiều project chạy cùng lúc (`project_required`);
- mode `[remote]`;
- Turbo chạy thật, HTTP/2 tới server thật, request chạy lâu.

Harness nằm ở `/private/tmp/claude-501/-Users-datnguyen-Projects-raijin/ebf0ea01-e67c-4787-844f-8f05f16b9b6a/scratchpad/h/`:
- `mcp_smoke.py`: driver;
- `phase_*.json`: các case;
- `audit.py`: kiểm invariant;
- `retries.json`: các `retry` đã thu.

Scratchpad có thể bị xoá. Nếu muốn giữ eval này thì nên chuyển vào `cli/` thành test.
