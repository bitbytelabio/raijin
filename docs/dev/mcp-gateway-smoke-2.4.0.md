# `raijin mcp` 2.4.0: smoke test, chỗ dễ lỗi, error message cho model yếu

Ngày 2026-11-26. CLI `raijin 2.4.0` (`~/.local/bin/raijin`), jar `build/libs/raijin.jar` 2.4.0 (cùng SHA-256 với `~/.local/bin/raijin.jar`), Burp Suite Pro 2026.10.1 headless, target `/Users/datnguyen/Projects/raijin`.

Cách test: client thật (Claude Code gọi `guide`/`run`) cộng JSON-RPC thô qua stdio cho cả hai era (legacy `initialize` 2025-06-18 và `server/discover` 2026-07-28).

## Những gì đã chạy được

| Mảng | Kết quả |
|---|---|
| Legacy `initialize` 2025-06-18 | tools `guide`, `run`; 9 prompts; 21 resource `skill://`; capability `extensions.io.modelcontextprotocol/skills` |
| 2026-07-28 `server/discover` | `supportedVersions` 2024-11-05 … 2026-07-28; `tools/list`, `tools/call`, `prompts/list` với `_meta` theo từng request đều OK. Thiếu `_meta` → `-32602` (rmcp làm đúng spec) |
| `guide` | overview, `tool`, `tool.action`, domain, playbook, file playbook (`http-testing/references/pipeline.md`) |
| `run` | một tool, grouped `tool.action`, `batch` với `bail` true/false, alias `tool` thay `do`, wrapper `arguments`, tên cũ `burp_version`, gọi thẳng `tools/call proxy_history` không qua `run` |
| Lifecycle | `burp_status`, `burp_up` (trả về pid, `version: 2.4.0`), `burp_down` |
| History offline | `history_list` khi Burp tắt |
| Spill | batch 30 KB > `inline_limit_kb = 24` → `{saved_to, bytes, preview, hint}` |
| Lỗi phía Kotlin | `unknown_parameter` + "did you mean 'request'", `unknown_action` + `did_you_mean`, `missing_action`, lỗi range (`length` 1–10000), thiếu tham số bắt buộc kèm `usage`, `project nope is not running; run {"do":"burp_up",...}` |
| Lenient phía Kotlin | `count: "2"`, `include_request: "false"`, `algorithm: "sha256"` đều được chấp nhận |

## Chỗ dễ lỗi, cần sửa

### P1: model nào cũng vấp

**1. Tool native (Rust) không ép kiểu string sang số/bool.**
- `run {"do":"history_list","limit":"1"}` → `history_list: invalid type: string "1", expected u64`. Lỗi tương tự với `burp_up` `wait_seconds` và `burp_down` `all`.
- Xảy ra thật trong phiên này: schema của `run` là `additionalProperties: true` nhưng không khai báo kiểu, nên Claude Code gửi các tham số top-level ở dạng string, và `burp_up {"wait_seconds":120}` fail ngay lần gọi đầu. Model yếu cũng hay tự đặt số trong ngoặc kép (`"limit":"5"`).
- Hai phía không nhất quán: Kotlin chấp nhận `"2"`, Rust thì không.
- Vị trí: `parse_args` (`cli/crates/raijin-cli/src/mcp/server.rs:251`) gọi thẳng `serde_json::from_value`.
- Cách sửa: trước `from_value`, duyệt `schema_of::<T>().properties`. Với giá trị string mà schema là `integer`/`number`/`boolean` (kể cả `["integer","null"]` và `anyOf`) thì parse sang kiểu đó; string chứa JSON mà schema là `array`/`object` thì parse JSON. Báo lại trong `notes` thay vì trả lỗi.

**2. Ví dụ trong mô tả `run` sai.** `{"do":"proxy_history","limit":5}`: `proxy_history` không có `limit` (tên đúng là `count`), nên copy nguyên văn sẽ nhận `unknown_parameter`. Ví dụ này nằm ở ba chỗ: `server.rs:298` (`MISSING_DO`), `server.rs:1198` (description của `run`) và `server.rs:1409` (lỗi unknown tool). Model yếu chép ví dụ y nguyên, nên call đầu tiên chắc chắn fail. Ngoài việc sửa ví dụ, nên đưa mọi ví dụ trong string của `server.rs` vào contract test (giống `every_cli_tool_call_in_the_skills_fits`) để chúng không lệch lại.

**3. Lỗi native là text thô của serde, khác envelope phía Kotlin.**
- `history_show: missing field \`ref\``
- `history_list: invalid value: integer \`-1\`, expected u64`
- `burp_up: unknown variant \`sideways\`, expected \`headless\` or \`ui\``
- `history_list: unknown parameter(s) lmit (did you mean limit?); expected comment, dedupe, ...`

Các lỗi này không phải JSON, không có `code`, `usage` hay `example`, và dùng thuật ngữ Rust (`u64`, `variant`, `field`). Trong khi đó instructions của server hứa "An error result says what to fix and often gives 'usage' and 'example'". Model parse JSON sẽ fail với text thuần. Cần map lỗi serde sang envelope chung (xem phần dưới).

### P2: model yếu vấp

**4. `batch` truyền dạng string JSON** → `run: batch must list at least one {"do":"<tool>", ...}` (`server.rs:631`). Thông báo chỉ sai nguyên nhân: batch có một step, chỉ là đang ở dạng string. Nên parse luôn string JSON, hoặc báo `'batch' must be a JSON array, got a string`.

**5. Tra cứu phân biệt hoa/thường.** `guide {"topic":"HTTP_SEND_REQUEST"}` → unknown topic, dù closest chính là `http_send_request`. `run {"do":"Burp.Version"}` → unknown tool (closest `burp_version`). Nên chuẩn hoá trước khi tra: lowercase, coi `.`, `_`, `-` là tương đương. Nếu sau chuẩn hoá chỉ khớp đúng một tên thì chạy luôn.

**6. Lỗi unknown topic dump cả overview (~3.5 KB)** (`server.rs:844`). Model context nhỏ tốn token, và dòng lỗi thật bị chìm trong đó. Chỉ nên trả `closest` kèm một dòng `guide() lists every tool`.

**7. `example: {}`** cho tool không có tham số bắt buộc (`proxy_history`). Một object rỗng không giúp được gì. Nên đưa một call điển hình: `{"do":"proxy_history","count":20}`.

**8. `example` của grouped tool thiếu `do`.** Ví dụ `{"action":"random_string","length":1}` khi đang gọi qua `run`: model copy lại sẽ mất `do`. Nên trả một call `run` hoàn chỉnh: `{"do":"util.random_string","length":10000}`.

**9. `did_you_mean: []` với `util.sha256`.** Edit distance không bắt được trường hợp này, nên cần thêm alias ngữ nghĩa: `sha256`/`md5`/... → `util.hash` + `algorithm`; `limit` → `count` (cho `proxy_history`); `raw_request` → `request` thì đã có.

**10. Gợi ý nhiễu khi không có match tốt.** `nope_tool` → `closest: scope_list, send_to_tool, burp_down`. Model yếu dễ chọn bừa một trong ba. Khi khoảng cách lớn thì không đưa tên nào, chỉ trỏ `guide()`.

### P3

**11. Chữ "offline" mơ hồ.** Domain `analysis` ghi "Offline analysis of requests…" nhưng vẫn cần Burp chạy (`util.base64_encode` khi Burp tắt → `no Burp running`). Ngược lại, `offline` của `history` nghĩa là không cần Burp. Đề xuất đổi thành "Local analysis (needs a running Burp; sends no traffic)".

**12. Lỗi enum từ handler không đồng nhất.** `util.hash algorithm:"SHA_999"` → `{"error":"Unsupported hash algorithm: 'SHA_999'. Supported: ..."}`: không có `code`, `usage` hay `allowed` như các lỗi validation khác.

**13. Tên prompt mất hậu tố `_skill`.** Từ 288f1e8, prompts có tên `overview`, `http-testing`, … Theo ghi chú trước đây, picker `/skill` của omp chỉ fuzzy-match theo tên, nên nhiều khả năng không thấy các prompt này. Claude Code thì vẫn thấy qua Skills extension (`raijin:overview`). Chưa kiểm trên omp.

## Error message để model yếu (DeepSeek, Qwen, GLM, model local) dùng được

Model yếu đọc dòng đầu, copy ví dụ, và hay gửi lại đúng call cũ. Error message nên được thiết kế để tận dụng ba thói quen đó.

### Envelope chung (Rust và Kotlin)

Luôn trả JSON với `isError: true`:

```json
{
  "error": "proxy_history has no parameter 'limit'; use 'count'.",
  "code": "unknown_parameter",
  "param": "limit",
  "got": 5,
  "expected": "count: integer",
  "retry": {"do": "proxy_history", "count": 5},
  "retryable": true,
  "usage": "proxy_history(start_index: integer, count: integer, host: string, ...)",
  "see": "guide {\"topic\":\"proxy_history\"}"
}
```

### Nguyên tắc

1. **Câu `error` đứng đầu và tự đủ nghĩa:** nói cái gì sai và làm gì tiếp, trong một câu ở thể mệnh lệnh. Không dùng thuật ngữ nội bộ (`u64`, `variant`, `serde`, `Option`, `field`); viết `integer ≥ 0`, `one of "headless", "ui"`, `required parameter`.
2. **`retry` là call `run` hoàn chỉnh, đã sửa sẵn:** có `do`, giữ nguyên các tham số đúng của call cũ, copy-paste là chạy được. Chỉ trả `retry` khi chắc chắn về bản sửa; nếu không thì trả `example`.
3. **Chỉ rõ vị trí lỗi:** `param`, `got` (giá trị đã nhận), `expected` (kiểu hoặc khoảng), `allowed` (với enum).
4. **`code` ổn định, dạng snake_case**, và playbook `overview` có bảng hướng dẫn xử lý cho từng code:

   | code | Model nên làm |
   |---|---|
   | `unknown_tool`, `unknown_action` | dùng `did_you_mean` hoặc gọi `guide` |
   | `unknown_parameter`, `missing_parameter`, `invalid_type`, `invalid_enum`, `out_of_range` | sửa theo `retry`/`usage` |
   | `burp_not_running`, `project_not_running` | `run {"do":"burp_up"}` rồi gửi lại |
   | `target_unreachable`, `timeout` | báo user hoặc đổi tham số, không lặp lại |
   | `internal` | dừng và báo user |

5. **`retryable` (true/false)** để chặn vòng lặp gửi lại y nguyên. Khi `false`, ghi thẳng `do not resend this call unchanged`.
6. **Ngắn:** khoảng 600 ký tự là đủ. Không dump overview hay toàn bộ schema; dùng `see` để trỏ tới `guide`.
7. **Dễ dãi ở đầu vào, chặt ở đầu ra:**
   - ép `"5"` → 5 và `"true"` → true; parse string JSON thành array hoặc object;
   - enum và tên tool không phân biệt hoa/thường, coi `-`, `_`, `.` là tương đương;
   - báo việc ép kiểu trong `notes` (`"coerced 'limit' from string"`) thay vì trả lỗi;
   - không đoán khi thao tác có tính phá huỷ (`burp_down`, `*.delete`, `*.remove`, `burp.shutdown`).
8. **Ví dụ phải chạy được.** Mọi ví dụ trong description, error message và playbook phải qua contract test trong CI. Một ví dụ sai còn tệ hơn không có ví dụ (xem P1-2).
9. **Batch:** lỗi của từng step dùng cùng envelope kèm `step`. Khi `bail`, trả thêm `not_run: [3, 4]`, và dòng tóm tắt ở top-level nói `step 2 of 4 failed: <error>`.
10. **Did-you-mean:** kết hợp edit distance với alias ngữ nghĩa, tối đa 3 gợi ý và chỉ khi đủ gần. Không có match tốt thì trỏ `guide()`.
11. **Văn bản thuần:** không markdown, không ANSI; tên field viết đúng như trong schema.

### Trước / sau

| Hiện tại | Đề xuất |
|---|---|
| `history_list: invalid type: string "1", expected u64` | tự ép kiểu, chạy, kèm `"notes":["coerced 'limit' from string"]` |
| `history_show: missing field \`ref\`` | `{"error":"history_show needs 'ref', a row ref from history_list such as \"main:12\".","code":"missing_parameter","param":"ref","example":{"do":"history_show","ref":"main:12"},"retryable":true}` |
| `burp_up: unknown variant \`sideways\`, expected \`headless\` or \`ui\`` | `{"error":"burp_up: 'mode' must be \"headless\" or \"ui\", got \"sideways\".","code":"invalid_enum","param":"mode","allowed":["headless","ui"],"retry":{"do":"burp_up","mode":"headless"}}` |
| `history_list: invalid value: integer \`-1\`, expected u64` | `{"error":"history_list: 'limit' must be an integer ≥ 0, got -1.","code":"out_of_range","param":"limit","retry":{"do":"history_list","limit":50}}` |
| `run: batch must list at least one {...}` (với batch dạng string) | parse string JSON; nếu không parse được thì `'batch' must be a JSON array of {"do":...} objects, got a string` |
| `unknown topic "HTTP_SEND_REQUEST"; closest: ...` + 3.5 KB overview | chuẩn hoá, trả luôn topic `http_send_request` |
| `example: {}` | `"example":{"do":"proxy_history","count":20}` |

## Test nên thêm

- Rust: unit test ép kiểu trong `parse_args`; contract test cho các ví dụ nằm trong string của `server.rs`; gateway test với `{"do":"history_list","limit":"1"}`.
- Một "weak-model eval" nhỏ: gửi lần lượt các call sai trong bảng dưới và assert mỗi lỗi đều là JSON, có `code`, và có `retry` hoặc `example` chạy được.

| Call sai | Hiện tại |
|---|---|
| `{}` | text, ví dụ sai (`limit`) |
| `{"do":"history_list","limit":"1"}` | fail, lỗi serde |
| `{"do":"burp_down","all":"maybe"}` | fail, lỗi serde |
| `{"do":"history_list","lmit":1}` | text, có gợi ý `limit` |
| `{"do":"history_show"}` | text `missing field` |
| `{"batch":"[{\"do\":\"burp.version\"}]"}` | báo sai nguyên nhân |
| `{"do":"Burp.Version"}` | unknown tool |
| `{"do":"util.sha256","data":"x"}` | `did_you_mean: []` |
| `{"do":"proxy_history","limit":2}` | JSON, tốt (gợi ý `count` qua `usage`) |
| `{"do":"scope.chek","url":"https://a.b"}` | JSON, tốt (`did_you_mean: ["check"]`) |
| `{"do":"util.random_string","length":999999}` | JSON, tốt (range kèm `example`) |
