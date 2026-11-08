# "Send to turbo intruder (with script from notes)" — Design

## Problem

Many organizer items have a Turbo Intruder script saved inside the `notes` annotation (the MCP `saveToOrganizer` tool and the in-app "Save to Organizer" both append the script there). Today, right-clicking such a request and choosing "Send to turbo intruder" opens the editor with the default sample script — the saved script is ignored.

We want a one-click path to reopen a request **with its previously-used script**.

## Approach

Add a **second** context menu item alongside the existing "Send to turbo intruder", labelled **"Send to turbo intruder (with script from notes)"**. It appears only when the selected request's notes contain a script marker. The original menu item is untouched, so users can still choose to start from a default script.

## Notes format

Both save paths write a marker so the script section is unambiguously parseable:

```
{user comment / notes}

{status info}

--- Script ---
{code}
```

- `McpToolHandlers.kt:62-66` already writes `--- Script ---`. No change.
- `RequestTable.kt:208` currently writes `{comment}\n{statusString}\n\n{code}` with no marker. Change to insert `\n--- Script ---\n` before `code`.

Sentinel: `--- Script ---`. Used verbatim. Last occurrence in the notes string delimits the script (so the marker may appear in the user comment without breaking extraction).

## Components

### 1. Script extraction helper (`OfferTurbo.kt`)

```kotlin
private const val SCRIPT_MARKER = "--- Script ---"

fun extractScriptFromNotes(notes: String?): String? {
    if (notes.isNullOrBlank()) return null
    val idx = notes.lastIndexOf(SCRIPT_MARKER)
    if (idx < 0) return null
    val script = notes.substring(idx + SCRIPT_MARKER.length).trim()
    return script.ifBlank { null }
}
```

### 2. New Montoya provider (`OfferTurbo.kt`)

```kotlin
class OfferTurboIntruderWithScript : ContextMenuItemsProvider {
    override fun provideMenuItems(event: ContextMenuEvent?): MutableList<Component> {
        if (event == null) return mutableListOf()
        val selected = event.selectedRequestResponses()
        if (selected.isEmpty()) return mutableListOf()
        val first = selected[0] ?: return mutableListOf()
        val script = extractScriptFromNotes(first.annotations()?.notes()) ?: return mutableListOf()

        val item = JMenuItem("Send to turbo intruder (with script from notes)")
        val resp = Resp(first)
        item.addActionListener(TurboIntruderFrame(resp, IntArray(0), script, null, null))
        return mutableListOf(item)
    }
}
```

Registered in `BurpExtender.kt:60-65` (the Montoya `initialize` method) alongside `BulkMenu`:

```kotlin
montoyaApi.userInterface().registerContextMenuItemsProvider(OfferTurboIntruderWithScript())
```

### 3. RequestTable.kt — add the marker

Change line 208 from:
```kotlin
val notes = comment + "\n" + handler.statusString() + "\n\n" + handler.code
```
to:
```kotlin
val notes = comment + "\n" + handler.statusString() + "\n\n--- Script ---\n" + handler.code
```

### 4. Unchanged

- `OfferTurboIntruder` (legacy `IContextMenuFactory`) — stays as-is. Provides the default-script entry point.
- `BulkMenu` — unchanged. Bulk selection has ambiguous script semantics, so it stays a default-script path.
- `McpToolHandlers.kt` — already writes the marker.

## Data flow

```
Right-click request → Burp invokes both providers
  ├─ OfferTurboIntruder (legacy)          → "Send to turbo intruder"
  └─ OfferTurboIntruderWithScript (Montoya)
       → reads selected[0].annotations().notes()
       → extractScriptFromNotes(notes)
       → if null: contributes nothing
       → if non-null: "Send to turbo intruder (with script from notes)"
                       → TurboIntruderFrame(..., fixedScript = script, ...)
                       → editor opens with the saved script preselected
```

`TurboIntruderFrame.getDefaultScript()` already honours `fixedScript` when non-null (`fast-http.kt:157-167`), so no change is needed there.

## Tests

`test/kotlin/OfferTurboTest.kt`:

- `extractScriptFromNotes` returns the script for `"comment\nstatus\n\n--- Script ---\ndef queueRequests(...): pass\n"`.
- Returns `null` for notes without the marker.
- Returns `null` for null, empty, or blank notes.
- Returns `null` when the marker is present but the trailing content is whitespace only.
- Returns content after the **last** marker when multiple occurrences exist (so users may freely mention `--- Script ---` in their comment).
- Trims trailing whitespace from the extracted script.

## Risk / trade-off

- Two menu items where there was one: small extra clutter, but explicit user choice was the point.
- Items saved to the organizer **before** the `RequestTable.kt` change won't have the marker, so the new menu item won't appear for them. Acceptable — they can be re-saved, or the user already knows the script.
- Lookup is on `selectedRequestResponses()[0]` only; if the user multi-selects, the new item appears based on the first item's notes. Same convention as `BulkMenu`.
