# `raijin mcp` 2.4.1: smoke test, chỗ dễ lỗi, error message cho model yếu

Ngày 2026-11-26. CLI `cli/target/release/raijin` 2.4.1 (HEAD `ca8048b`, server `.mcp.json` của repo), jar `build/libs/raijin.jar` build lại từ HEAD, Burp Suite Pro 2026.10.1 headless, target `/Users/datnguyen/Projects/raijin`. Bản trước: `mcp-gateway-smoke-2.4.0.md`.

Cách test: 163 call JSON-RPC thô qua stdio (86 khi Burp tắt, 67 khi Burp chạy, 10 trên era 2026-07-28), vài call qua client thật (Claude Code `guide`/`run`), và `curl` thẳng vào `/api/v1`. Phần lớn là call sai kiểu model yếu hay gửi.

Tác dụng phụ: archive của project `main` có thêm khoảng 5 exchange `http_send_request` tới `127.0.0.1:1` (port đóng). Có một file spill trong `.raijin/tool-results/`. Thư mục `.raijin/exports/` do `history_export` tạo ra đã được xoá. Burp đã tắt lại.

## Trạng thái sau khi sửa (2026-11-27, chưa release)

Kiểm bằng test, chưa chạy lại harness với Burp thật. Chi tiết ở `CHANGELOG.md` (Unreleased).

| # | Trạng thái | Ở đâu / test |
|---|---|---|
| P1-1 tên lạ khi Burp tắt | Đã sửa | `Catalog::resolve_call`, `Gateway::unreached`; `weak_model_calls_while_burp_is_down` |
| P1-2 lỗi handler thiếu `code` | Đã sửa | `ToolArgs.enrich` (fallback cho mọi lỗi), base64/turbo/collaborator/findings/raw request thiếu Host; `every handler error becomes an envelope with a code` |
| P1-3 `headers:["X-A: 1"]` | Đã sửa | `JsonHelpers.asHeaders`; entry không đọc được → `invalid_type`, không gửi |
| P1-4 `bail:"true"` | Đã sửa | `read_bail`; `weak_model_batches_synonyms_and_history_errors` |
| P2-5 alias một chiều | Đã sửa | `PARAM_SYNONYMS` (Kotlin + Rust, `param_synonyms` trong catalog, test so khớp) |
| P2-6 `input` bị coi là wrapper | Đã sửa | `normalize_run`: chỉ object mới là wrapper (trừ `arguments`) |
| P2-7 lỗi history | Đã sửa | `history::Problem`, `history_error`; `ToolError::new` tự thêm dấu chấm |
| P2-8 `example` phía Kotlin | Đã sửa | `ToolExamples` + `ToolExamplesTest` (khớp schema, không destructive, `burp` → `version`) |
| P2-9 lỗi Kotlin thiếu `param` | Phần lớn | `enrich` suy `param`/`got`/`expected`; `random_string` clamp; `analyze.request`, `turbo_docs` (`allowed` thay `available_topics`) |
| P2-10 `guide` | Đã sửa | narrow theo action, `usage`/`example`, `sha256`, `run`, `skill://...`, `name`/`tool` |
| P2-11 `do:"guide"` | Đã sửa | `gateway_tool_as_do` |
| P2-12 port đóng | Đã sửa | `no_response`, `time_request_sent: null` |
| P3-13 envelope/ký pháp | Phần lớn | `usage` dạng `util.hash(...)`, `allowed`, bỏ `unknown_parameters` và mảng rỗng. Description của tool nhóm vẫn ở dạng `{"action":...}` vì client `/mcp` gọi theo dạng đó |
| P3-14 input lạ | Đã sửa | `{"do":5}`, `steps`, step dạng string |
| P3-15 `proxy_history` lớn | Đã sửa | mặc định 20 item, `request_headers` chỉ khi `include_headers` |
| P3-16 mã lỗi resource | Đã sửa | `-32002` cho `skill://` và `burp://` |
| P3-17 HTTP 400/415 | Đã sửa | `respondError` có `code`, `retryable` |
| P3-18 `notes` | Đã sửa | parse JSON string sang object/array có note |

## Các mục của bản 2.4.0

| # (2.4.0) | Trạng thái | Bằng chứng |
|---|---|---|
| 1 ép kiểu ở tool native | **Đã sửa** | `history_list limit:"1"` chạy, có `notes: coerced 'limit' from string`. Client thật: `burp_up wait_seconds` (Claude Code gửi dạng string) cũng chạy |
| 2 ví dụ sai trong `run` | **Đã sửa** | mọi ví dụ giờ là `{"do":"proxy_history","count":20}`, có test `every_example_in_the_gateway_text_runs` |
| 3 lỗi serde thô | **Đã sửa** | `invalid_type`, `out_of_range`, `invalid_enum`, `missing_parameter` đều kèm `param`, `usage`, `example` |
| 4 `batch` dạng string | **Đã sửa** | parse được, có `notes`; string không phải JSON thì báo `'batch' must be a JSON array` |
| 5 phân biệt hoa/thường | **Đã sửa** | `History.List`, `history list`, `history-list`, `Burp.Version`, `guide HTTP_SEND_REQUEST` |
| 6 unknown topic dump overview | **Đã sửa** | còn khoảng 170 B kèm `did_you_mean` |
| 7 `example: {}` | **Còn một phần** | phía Rust đã ổn. Phía Kotlin vẫn có ví dụ trơn (P2-8) |
| 8 example thiếu `do` | **Đã sửa** | `retry`/`example` đều ở dạng `{"do":"scope.check",...}` |
| 9 `util.sha256` | **Còn một phần** | `run` thì chạy được (`util.sha256`, `sha256`, `md5`). `guide` thì không (P2-10) |
| 10 gợi ý nhiễu | **Còn** | `guide nope` → `["scope"]`; Tool API `nope` → "Did you mean 'scope'?" |
| 11 chữ "offline" | **Đã sửa** | domain `analysis` giờ ghi "Local analysis ... in the running Burp" |
| 12 lỗi enum của handler | **Đã sửa** | `util.hash algorithm:SHA_999` → `invalid_enum` kèm `allowed` |
| 13 prompt trên omp | Chưa kiểm | |

Chạy tốt: handshake legacy và 2026-07-28 (`server/discover` có `_meta`; thiếu `_meta` → `-32602`), resources `skill://` + `burp://` (8 cái khi Burp chạy), spill `{saved_to, bytes, preview, hint}`, batch `bail` với `not_run`/`stopped_after`, tên tool destructive viết sai hoa/thường không bị chạy (`BURP_DOWN`, `Scope.Remove`, `Burp.Shutdown` đều trả `unknown_tool` kèm `retry` dùng tên chính xác), Host check (`Host: evil.com` → 403). Tham số `name` của tool (`turbo_docs.get_example`) không bị nhầm thành alias của `do`.

## Chỗ dễ lỗi, cần sửa

### P1: lỗi sai hướng hoặc làm sai mà không báo

**1. Khi Burp tắt, mọi tên mà CLI không sở hữu đều nhận `burp_not_running`, kể cả tên không tồn tại.**
- `run {"do":"nope_tool"}`, `{"do":"scope.chek"}`, `{"do":"guide"}`, `{"do":"run"}` đều trả `no Burp running ...; run {"do":"burp_up"} first`.
- Hậu quả: model chạy `burp_up` (mất 30–60 s), gửi lại, rồi mới nhận `unknown_tool`. Model yếu dễ quên luôn call gốc sau bước vòng này.
- Nguyên nhân: `endpoint()` (`cli/crates/raijin-cli/src/mcp/server.rs:594`) chạy trước bước tra tên, trong khi CLI đã có catalog lúc offline (`guide` vẫn liệt kê đủ tool khi Burp tắt).
- Sửa:
  - tra tên theo `catalog/tools.json` trước (cùng luật với `ToolNames`);
  - tên không có thì trả `unknown_tool` ngay khi offline;
  - tên có thì trả `burp_not_running` với `retry` là một call hoàn chỉnh: `{"batch":[{"do":"burp_up"},{<call gốc>}],"bail":true}`;
  - `do: "guide"`/`"run"` thì xử lý tại chỗ (xem P2-11).

**2. Lỗi từ handler không đi qua envelope: không có `code`, không có `retryable`.**

| Call | Kết quả |
|---|---|
| `util.base64_decode data:"!!!not base64"` | `{"error":"Illegal base64 character 21"}` (`21` là mã hex của `!`) |
| `turbo_run.status run_id:"nope"` | `{"error":"not_found"}` |
| `collaborator.poll client_id:"nope"` | `{"error":"Client not found: nope"}` |
| `findings.remove id:"nope"` | `{"id":"nope","removed":false,"error":"Finding not found: nope","total_findings":0}` |
| `http_send_request raw_request:"GET / HTTP/1.1\r\n\r\n"` | `{"scope_warning":"... for  (Invalid URL) ...","error":"Failed to send request: HTTP service cannot be null",...}` |

- Nguyên nhân: `ToolArgs.enrich` (`src/main/kotlin/io/bitbytelab/raijin/tools/ToolArgs.kt:282`) chỉ gắn `code` khi `error` khớp regex `ARGUMENT_ERROR`. Câu nào không khớp thì giữ nguyên, nên lời hứa "every error is one JSON object with code" không đúng hết.
- Sửa:
  - Thêm fallback trong `enrich`: mọi kết quả `isError` đều phải có `code` và `retryable`. Lỗi kiểu "not found" thành `not_found` (retryable) kèm `see` trỏ tới action liệt kê: `turbo_run.list`, `collaborator.list_clients`, `findings.list`. Còn lại thành `tool_failed`.
  - Lâu dài: handler trả lỗi có kiểu (not found / bad argument), không để regex đoán.
  - Riêng raw request thiếu Host: báo `raw_request has no Host header; add one or pass 'host', 'port', 'use_tls'` kèm `example`.

**3. `headers` dạng `["X-A: 1"]` bị bỏ mà không báo lỗi, request vẫn được gửi.**
- Kết quả là `isError: false` và `headers_warning: "1 of 1 header entries could not be parsed"`. Request lên wire thiếu header, trong khi model yếu bỏ qua warning nằm trong một kết quả thành công.
- Vị trí: `tools/http/HttpTools.kt:153`.
- Sửa:
  - chấp nhận string `"Name: value"`: tách ở dấu `:` đầu tiên, giữ nguyên byte của value (không vi phạm luật "never restrict what can be sent");
  - entry nào vẫn không parse được thì trả lỗi và không gửi. Gửi một request khác với ý định còn tệ hơn là không gửi.

**4. `bail: "true"` (string) bị coi là `false` mà không báo.** Batch `[history_show (lỗi), burp_status]` với `bail:"true"` vẫn chạy step 2. Nguyên nhân: `raw.get("bail").and_then(Value::as_bool)` (`server.rs:726`) không ép kiểu như mọi chỗ khác. Hệ quả nguy hiểm khi các step sau có thao tác ghi.

### P2: model yếu vấp

**5. Mỗi tool dùng một bộ tên tham số, và alias chỉ có một chiều.** Đây là nguồn `unknown_parameter` lớn nhất trong lần test này.

| Call | Kết quả |
|---|---|
| `history_list count:1` | không gợi ý `limit` |
| `history_search query:"(" regex:true` | không gợi ý `pattern` |
| `proxy_history_search query:"google"` | `did_you_mean: []` |
| `sitemap.query count:"1"` | `did_you_mean: []` (tên đúng là `max_results`) |
| `util.hash text:"x"` | `did_you_mean: []` (tên đúng là `data`) |
| `util.base64_encode value:"x"` | `did_you_mean: []` (tên đúng là `data`) |

- Hiện trạng: `PARAM_ALIASES` (`ToolArgs.kt:231`) map `limit`/`max_results` → `count`, nhưng không có chiều `count` → `max_results`/`limit`. Phía Rust (`mcp/args.rs`) không có alias nào.
- Sửa: dùng nhóm tương đương thay cho map một chiều. Mỗi tên trong nhóm được map sang tên mà tool khai báo. Rust và Kotlin dùng chung một bảng (ví dụ sinh vào `catalog/tools.json`). Các nhóm:
  - `{count, limit, max, max_results, max_items, size}`
  - `{start_index, offset, skip}`
  - `{pattern, query, q, regex, search, search_pattern}`
  - `{data, input, text, value, string}`
  - `{url, uri}`
  - `{request, raw_request}`
  - `{response, raw_response}`

  Chỉ trả `retry` khi đổi tên xong là chắc chắn đúng.

**6. `input` bị `run` hiểu là wrapper chứa tham số.** `{"do":"util.hash","input":"x","algorithm":"MD5"}` → `run: 'input' must be a JSON object of the tool's parameters`. Sửa: chỉ coi `input`/`args`/`params`/`parameters` là wrapper khi giá trị là object (hoặc string JSON của một object) và tool không khai báo tham số đó. Trường hợp còn lại thì để alias ở P2-5 xử lý (`input` → `data`).

**7. Lỗi user tự sửa được lại bị đánh `tool_failed` với `retryable: false`.**
- Các case:
  - `history_show ref:"nope"` → `bad ref "nope": expected ...`
  - `history_show ref:"main:999999"` → `no proxy entry ...`
  - `history_list project:"nope"` → `no project "nope"; known: main`
- Ba case này nên là `invalid_arguments`, `not_found`, và `invalid_enum` với `allowed:["main"]`, đều `retryable: true`.
- Lỗi chấm câu: `FINAL_SENTENCE` (`mcp/error.rs:13`) được nối sau một câu không có dấu chấm, ra `known: main Do not resend this call unchanged.` Các câu gốc nằm ở `history/mod.rs:228`, `history/source.rs:107`.
- Sửa: `ToolError::new` tự thêm `.` khi câu chưa kết thúc bằng dấu câu.

**8. Phía Kotlin có `example` không chạy được hoặc vô dụng.**

| Tool | `example` hiện tại | Vấn đề |
|---|---|---|
| `http_send_request` | `{"do":"http_send_request"}` | thiếu `url` hoặc `raw_request` bắt buộc |
| `proxy_history` | `{"do":"proxy_history"}` | trơn |
| `sitemap.query` | `{"do":"sitemap.query"}` | trơn |
| `turbo_docs.get_docs` | không có `topic` | trơn |
| `util.random_string` | `length:1` | đúng nhưng vô dụng |
| `burp` (thiếu action) | `burp.import_project_config` với `config_json:"<config_json>"` | chọn trúng một action ghi kèm placeholder |

Sửa: mỗi tool/action có một `example` chọn tay trong catalog: read-only, giá trị thật (`https://example.com/`, `count: 20`), không dùng placeholder khi có thể. Thêm một contract test Kotlin: mọi `example` phải qua được validation của chính tool đó.

**9. Lỗi phía Kotlin thiếu `param`/`got`/`expected`, và mã lỗi khác với phía Rust.**

| Call | Kotlin | Rust (cùng loại lỗi) |
|---|---|---|
| `proxy_history count:2.5` | `invalid_arguments` "Parameter 'count' must be an integer", không có `param` | `invalid_type` kèm `param`, `got`, `expected` |
| `util.random_string length:999999` | `invalid_arguments`, không có `param`/`got`. Bị từ chối, trong khi `proxy_history count:1000000` thì được clamp kèm note (CLAUDE.md: "Oversized limits are clamped and reported") | `out_of_range` |
| `scope.check url:"not a url"` | `"Invalid URL"`, không có `param` | |
| `analyze.request request:123` | `"URL is invalid."`: sai hướng, vì tham số là raw HTTP request chứ không phải URL | |
| `turbo_docs.get_docs topic:"nope"` | `"error":"unknown_topic"` (field `error` chứa code chứ không phải câu), `available_topics` lặp lại `allowed` | |
| `turbo_docs.get_example name:"nope"` | `"error":"not_found"` | |

**10. `guide` chưa đưa model thứ nó cần để gọi đúng ngay lần đầu.**
- `guide util.hash` trả nguyên schema của `util` (3.6 KB, params của mọi action, có tag `[hash]`) thay vì chỉ params của `hash`.
- Output của `guide` không có `usage` hay `example`; hai thứ này chỉ xuất hiện trong lỗi. Model phải tự đọc JSON Schema (`$defs`, `anyOf`, `oneOf`, `format: uint64` ở tool native).
- `guide util.sha256` và `guide sha256` → unknown topic, dù `run` nhận cả hai.
- `guide run`/`guide guide` → unknown topic, gợi ý `turbo_run`, `bcheck_dry_run`.
- `guide skill://overview/SKILL.md`, `guide /overview` → unknown topic (`did_you_mean: overview`). Nên tự bỏ tiền tố `skill://`, dấu `/` đầu và đuôi `SKILL.md`.
- `guide {"name":"history_list"}` → `unknown_parameter` không có gợi ý. Nên nhận `name`/`tool` làm alias của `topic`.

**11. `run {"do":"guide"}` khi Burp chạy** → `Unknown tool 'guide'`, `did_you_mean: []`. Nên trả: `guide is its own tool: call guide {"topic":"..."}, not run`, kèm `see`.

**12. `http_send_request` tới port đóng:**
- trả `isError:false`, `has_response:false`, không có lý do;
- `timing.time_request_sent: "1970-01-01T08:00..."` (epoch 0).

Model không phân biệt được connection refused, timeout hay response rỗng. Nên thêm một field ngắn, ví dụ `no_response: "no response from 127.0.0.1:1 (refused, reset or timed out)"`, và trả `null` cho timestamp khi chưa gửi được.

### P3

**13. Envelope phía Rust và Kotlin vẫn khác hình dạng.**
- Kotlin trả mảng rỗng (`did_you_mean: []`), có `unknown_parameters`, và dùng `available` cho action, trong khi phía Rust và các field enum dùng `allowed`.
- Ký pháp lẫn lộn:
  - `usage` và câu lỗi phía Kotlin: `util(action="hash", data*: string)`, `scope(action='check')`;
  - `retry`/`example`: `{"do":"util.hash"}`;
  - description: `{"action":"url_encode",...}`.

  Model yếu copy ký pháp nào gặp đầu tiên. Nên dùng một dạng duy nhất: `util.hash(data*: string, algorithm*: "MD5"|...)`.

**14. Một số dạng input của model yếu chưa nhận ra.**
- `{"do":5}` → "run needs do"; nên là `invalid_type`.
- `{"steps":[...]}` → "run needs do"; nên nhận như `batch` hoặc gợi ý `batch`.
- batch `["burp_status","history_list"]` → "batch cannot nest": báo sai nguyên nhân. Nên coi step dạng string `s` là `{"do":s}`.

**15. `proxy_history` không tham số trả 22 KB cho 25 item** (có kèm headers), sát `inline_limit_kb = 24`. Với history thật thì gần như call trơn nào cũng bị spill. Nên giảm default (20 item, không kèm headers).

**16. Mã lỗi resource không thống nhất.** `skill://nope` → `-32602`, còn `burp://nope` → `-32603` (internal). MCP dùng `-32002` cho resource not found.

**17. Lỗi HTTP 400/415 của Tool API** (`body must be a JSON object`, `Content-Type must be application/json`) không có `code`. Chỉ ảnh hưởng client gọi thẳng `/api/v1`.

**18. `notes` không đều.** `headers` gửi dạng string JSON được ép sang object mà không có note; `verify_tls:"false"` thì có.

## Error message để model yếu (DeepSeek, Qwen, GLM, model local) dùng được

Nguyên tắc của bản 2.4.0 vẫn đúng và phần lớn đã được làm. Lần test này cho thêm mấy bài học dưới đây, xếp theo số lỗi chúng ngăn được. Mình chưa chạy DeepSeek thật; các thói quen bên dưới (quote số, dùng tên kiểu OpenAI như `limit`/`query`/`input`, copy ví dụ y nguyên, bỏ qua warning trong kết quả thành công, lặp lại call cũ) lấy từ hai lần smoke test và cách Claude Code gửi tham số.

1. **Bảo đảm 100%, kiểm ở một chỗ.** Mọi kết quả `isError` đều có `error` (một câu), `code` và `retryable`. Bước kiểm cuối nằm ở một chỗ duy nhất: fallback trong `enrich` cho Kotlin, `ToolError` cho Rust. Có test duyệt toàn bộ catalog để giữ điều này. Một lỗi thiếu `code` làm hỏng bảng xử lý theo `code` trong playbook `overview`.
2. **`error` là câu chứ không phải mã:** `<tool>: <cái gì sai>. <làm gì tiếp>.` Luôn kết thúc bằng dấu chấm, rồi mới nối `Do not resend ...`. Không để lộ chi tiết nội bộ (`HTTP service cannot be null`, `character 21`, `u64`).
3. **`retry` gói luôn bước đi vòng.** Với `burp_not_running`, `retry = {"batch":[{"do":"burp_up"},<call gốc>],"bail":true}`. Model yếu hay mất call gốc sau một bước đi vòng; một call copy-paste chạy được thì không có chỗ nào để quên.
4. **Một bộ từ vựng và alias theo nhóm** (P2-5). Model yếu mang tên tham số từ tool khác hoặc từ API kiểu OpenAI sang. Map theo nhóm tương đương rẻ hơn nhiều so với hy vọng model đọc `usage`.
5. **Một ký pháp ở mọi nơi**: description, `usage`, `example`, `retry`, playbook. Dạng gọi là `{"do":"util.hash",...}`, chữ ký là `util.hash(data*: string, ...)`. Nhiều ký pháp thì model sẽ trộn chúng lại với nhau.
6. **Phòng lỗi trước khi nó xảy ra:** output của `guide <tool.action>` có đúng ba thứ ngắn: `usage`, `example` (chạy được), và schema đã thu hẹp về action đó. Lỗi rẻ nhất là lỗi không xảy ra.
7. **Ví dụ thật và được test:** read-only, có giá trị cụ thể, đủ tham số bắt buộc. Contract test cho mọi `example` ở cả hai phía. Một `{"do":"http_send_request"}` trơn còn tệ hơn không có ví dụ.
8. **Dễ dãi không có nghĩa là bỏ qua.** Thứ gì không hiểu được thì báo lỗi; ép kiểu được thì ép và ghi `notes`. Không bao giờ âm thầm bỏ dữ liệu (header ở P1-3, `bail` ở P1-4). Riêng tool pentest: request sai so với ý định là lỗi nặng nhất.
9. **Not found trỏ tới action liệt kê:** `{"code":"not_found","see":{"do":"turbo_run.list"}}`. Model yếu không tự nghĩ ra là cần liệt kê trước.
10. **`retryable` phải phản ánh đúng việc caller có tự sửa được không:** ref sai, project sai, URL sai là `true`. `false` chỉ dành cho lỗi ngoài tầm của call (`raijin_unreachable`, `internal`, `not_supported`).
11. **Kết quả "không có gì xảy ra" cũng cần lý do**: `has_response:false` phải kèm một câu giải thích (P2-12). Model yếu đọc `isError:false` là thành công.
12. **Field thống nhất:** `allowed` (không dùng `available` hay `available_topics`), bỏ hẳn field rỗng, `did_you_mean` chỉ có khi đủ gần.

### Trước / sau

| Hiện tại | Đề xuất |
|---|---|
| Burp tắt, `{"do":"nope_tool"}` → `burp_not_running` | `{"error":"unknown tool \"nope_tool\"; guide {} lists every tool.","code":"unknown_tool","retryable":true,"see":"guide {}"}` |
| Burp tắt, `{"do":"util.hash",...}` → `example: {"do":"burp_up"}` | `"retry":{"batch":[{"do":"burp_up"},{"do":"util.hash","data":"x","algorithm":"MD5"}],"bail":true}` |
| `{"error":"not_found"}` (turbo) | `{"error":"turbo_run: no run \"nope\". List runs with turbo_run.list.","code":"not_found","param":"run_id","got":"nope","see":{"do":"turbo_run.list"},"retryable":true}` |
| `{"error":"Illegal base64 character 21"}` | `{"error":"util.base64_decode: 'data' is not base64 (bad character '!' at 0).","code":"invalid_arguments","param":"data","retryable":true}` |
| `headers:["X-A: 1"]` → bị bỏ, vẫn gửi | header được parse; entry không parse được → `invalid_type` kèm `param:"headers"`, không gửi |
| `sitemap.query count:1` → `did_you_mean: []` | `retry: {"do":"sitemap.query","max_results":1}` |
| `no project "nope"; known: main Do not resend ...` (`tool_failed`) | `{"error":"history_list: no project \"nope\".","code":"invalid_enum","param":"project","allowed":["main"],"retry":{"do":"history_list","project":"main"},"retryable":true}` |
| `example: {"do":"http_send_request"}` | `"example":{"do":"http_send_request","url":"https://example.com/"}` |
| `usage: util(action="hash", data*: string, ...)` | `usage: util.hash(data*: string, algorithm*: "MD5"\|"SHA_1"\|...)` |

## Test nên thêm

- **Kotlin, `ToolApiTest`:** duyệt mọi tool/action trong catalog và gửi `{}`, từng tham số sai kiểu, và một id không tồn tại. Assert kết quả là JSON có `error` (string kết thúc bằng dấu câu), `code` thuộc tập đã biết, và `retryable`. Assert mọi `example`/`retry` qua được validation của chính tool đó.
- **Rust, `mcp_gateway.rs`:** khi offline, `{"do":"nope_tool"}` → `unknown_tool`; `bail:"true"` dừng batch; `FINAL_SENTENCE` sau câu không có dấu chấm; alias `count` → `limit` cho `history_list`, `query` → `pattern` cho `history_search`.
- **Weak-model eval** (chạy lại với harness của lần này; ghi `ok` khi đã đạt):

| Call | Hiện tại |
|---|---|
| Burp tắt: `{"do":"scope.chek","url":"https://a.b"}` | `burp_not_running` (sai hướng) |
| `{"batch":[{"do":"history_show"},{"do":"burp_status"}],"bail":"true"}` | chạy cả step 2 |
| `{"do":"http_send_request","url":"http://127.0.0.1:1/","headers":["X-A: 1"]}` | header bị bỏ |
| `{"do":"util.base64_decode","data":"!!!"}` | không có `code` |
| `{"do":"turbo_run.status","run_id":"nope"}` | `{"error":"not_found"}` |
| `{"do":"sitemap.query","count":1}` | `did_you_mean: []` |
| `{"do":"util.hash","input":"x","algorithm":"MD5"}` | bị coi là wrapper |
| `{"do":"history_list","project":"nope"}` | `tool_failed`, không retryable |
| `{"do":"http_send_request"}` | `example` thiếu `url` |
| `guide {"topic":"util.hash"}` | trả schema của cả `util` |
| `{"do":"history_list","limit":"1"}` | ok |
| `{"do":"Burp.Version"}` | ok (`notes`) |
| `{"do":"proxy_history","limit":2}` | ok (`retry` với `count`) |
| `{"do":"BURP_DOWN"}` | ok (không chạy, `retry` dùng tên chính xác) |

## Chưa kiểm

DeepSeek/Qwen thật; picker `/skill` của omp; nhiều project chạy cùng lúc (`project_required`); mode `[remote]`; timeout của request dài; HTTP/2 và Turbo chạy thật. Harness tạm ở `/private/tmp/claude-501/-Users-datnguyen-Projects-raijin/7c2684e6-957e-4d20-aaf9-5874cb0d2cf3/scratchpad/harness/mcp_smoke.py` (scratchpad, có thể bị xoá). Nếu muốn giữ để chạy lại eval thì nên chuyển vào `cli/` thành test.
