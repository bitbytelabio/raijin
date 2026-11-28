//! Human and touch input through the `Motion` CDP domain of `ShardBrowser`'s engine. The domain
//! needs a session on a page target: the engine's active page session is one. Ports the
//! `human_*`, `touch_*` and `rotate_screen` tools of the launcher's Node MCP server.

use std::time::Duration;

use rmcp::model::CallToolResult;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::OwnedMutexGuard;

use super::page::Session;
use super::{Call, Hub, json_result, text_result};
use crate::mcp::error::{Code, ToolError};

/// Motion commands take human time; typing a paragraph can run for minutes.
const MOTION_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfileArgs {
    pub profile_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PointArgs {
    pub profile_id: String,
    /// CSS, xpath= or a snapshot ref (@e3); else give x and y.
    pub selector: Option<String>,
    pub x: Option<f64>,
    pub y: Option<f64>,
    /// From the element's left edge (default its middle).
    pub offset_x: Option<f64>,
    /// From the element's top edge (default its middle).
    pub offset_y: Option<f64>,
    /// Start the profile without a window when it is not running.
    pub headless: Option<bool>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Button {
    Left,
    Middle,
    Right,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HumanClickArgs {
    pub profile_id: String,
    /// CSS, xpath= or a snapshot ref (@e3); else give x and y.
    pub selector: Option<String>,
    pub x: Option<f64>,
    pub y: Option<f64>,
    pub offset_x: Option<f64>,
    pub offset_y: Option<f64>,
    /// On a phone, right is a long press.
    pub button: Option<Button>,
    /// 1 to 3.
    #[schemars(range(min = 1, max = 3))]
    pub click_count: Option<u32>,
    pub headless: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HumanTypeArgs {
    pub profile_id: String,
    pub text: String,
    pub allow_typos: Option<bool>,
    pub headless: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HumanFillArgs {
    pub profile_id: String,
    /// CSS, xpath= or a snapshot ref (@e3).
    pub selector: String,
    pub text: String,
    /// Select the old value first (a triple click; on a phone the field is emptied); without it
    /// the text is appended.
    pub clear: Option<bool>,
    pub allow_typos: Option<bool>,
    pub headless: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TouchTapArgs {
    pub profile_id: String,
    pub selector: Option<String>,
    pub x: Option<f64>,
    pub y: Option<f64>,
    pub offset_x: Option<f64>,
    pub offset_y: Option<f64>,
    /// 2 is a double tap with a realistic gap and offset; 1 to 3.
    #[schemars(range(min = 1, max = 3))]
    pub tap_count: Option<u32>,
    pub headless: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TouchLongPressArgs {
    pub profile_id: String,
    pub selector: Option<String>,
    pub x: Option<f64>,
    pub y: Option<f64>,
    pub offset_x: Option<f64>,
    pub offset_y: Option<f64>,
    /// Omit for the profile's own hold; the engine floors it above the long-press threshold.
    pub hold_ms: Option<f64>,
    pub headless: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TouchSwipeArgs {
    pub profile_id: String,
    /// Start here (default: the middle of the viewport).
    pub selector: Option<String>,
    pub x: Option<f64>,
    pub y: Option<f64>,
    pub dx: Option<f64>,
    pub dy: Option<f64>,
    pub to_x: Option<f64>,
    pub to_y: Option<f64>,
    /// true lifts the finger while it still moves (flings the page); omit to let the profile decide.
    pub flick: Option<bool>,
    pub headless: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TouchDragArgs {
    pub profile_id: String,
    pub selector: Option<String>,
    pub x: Option<f64>,
    pub y: Option<f64>,
    pub to_selector: Option<String>,
    pub to_x: Option<f64>,
    pub to_y: Option<f64>,
    pub hold_ms: Option<f64>,
    pub headless: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TouchPinchArgs {
    pub profile_id: String,
    /// Above 1 zooms in, below 1 zooms out; more than 0.
    pub scale: f64,
    /// Pinch here (default: the middle of the viewport).
    pub selector: Option<String>,
    pub x: Option<f64>,
    pub y: Option<f64>,
    /// Degrees the line between the fingers turns; omit for the profile's own.
    pub rotation: Option<f64>,
    pub headless: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RotateArgs {
    pub profile_id: String,
    /// 0, 90, 180 or 270, clockwise from the profile's own orientation.
    pub angle: i64,
    /// Omit for the profile's own; the engine clamps it to 400-2000 ms.
    pub turn_ms: Option<f64>,
    pub headless: Option<bool>,
}

/// A point to aim at, with the target's width when an element was named.
#[derive(Debug, Clone, Copy)]
struct Point {
    x: i64,
    y: i64,
    width: Option<i64>,
}

impl Point {
    fn at(self) -> String {
        format!("{},{}", self.x, self.y)
    }
}

/// Where to aim: an element (with an offset into it), or a point.
#[derive(Debug, Clone, Copy, Default)]
struct Aim<'a> {
    selector: Option<&'a str>,
    x: Option<f64>,
    y: Option<f64>,
    offset_x: Option<f64>,
    offset_y: Option<f64>,
}

impl<'a> Aim<'a> {
    fn element(selector: &'a str) -> Self {
        Self {
            selector: Some(selector),
            ..Self::default()
        }
    }

    fn point(x: Option<f64>, y: Option<f64>) -> Self {
        Self {
            x,
            y,
            ..Self::default()
        }
    }
}

/// Rounds a CSS pixel value to the integer the Motion domain takes.
#[allow(clippy::cast_possible_truncation)]
fn px(v: f64) -> i64 {
    v.round() as i64
}

fn duration_ms(result: &Value) -> Value {
    result.get("durationMs").cloned().unwrap_or(json!(0))
}

fn in_range(param: &str, value: Option<u32>, max: u32) -> Result<(), ToolError> {
    match value {
        Some(v) if !(1..=max).contains(&v) => Err(ToolError::new(
            Code::OutOfRange,
            format!("{param} must be 1 to {max}, got {v}"),
        )
        .param(param)
        .got(json!(v))
        .expected(format!("1 to {max}"))),
        _ => Ok(()),
    }
}

/// Sends a Motion command on the active page session.
async fn send(session: &Session, method: &str, params: Value) -> Result<Value, ToolError> {
    let browser = session
        .state
        .browser
        .as_ref()
        .ok_or_else(|| ToolError::new(Code::ToolFailed, "browser not attached"))?;
    let sid = active_sid(session)?;
    browser
        .client
        .send_command_with_timeout(method, Some(params), Some(&sid), MOTION_TIMEOUT)
        .await
        .map_err(|e| ToolError::new(Code::ToolFailed, format!("{method}: {e}")))
}

fn active_sid(session: &Session) -> Result<String, ToolError> {
    let browser = session
        .state
        .browser
        .as_ref()
        .ok_or_else(|| ToolError::new(Code::ToolFailed, "browser not attached"))?;
    browser
        .active_session_id()
        .map(str::to_owned)
        .map_err(|e| ToolError::new(Code::ToolFailed, e))
}

impl Hub {
    pub(super) async fn motion(&self, call: &mut Call<'_>) -> Result<CallToolResult, ToolError> {
        let value = match call.action.name {
            "human_release_pointer" => {
                let ProfileArgs { profile_id } = call.args()?;
                self.release_pointer(&profile_id).await;
                return Ok(text_result("pointer released"));
            }
            "human_move" => self.human_move(call.args()?).await?,
            "human_click" => self.human_click(call.args()?).await?,
            "human_type" => self.human_type(call.args()?).await?,
            "human_fill" => self.human_fill(call.args()?).await?,
            "touch_tap" => self.touch_tap(call.args()?).await?,
            "touch_long_press" => self.touch_long_press(call.args()?).await?,
            "touch_swipe" => self.touch_swipe(call.args()?).await?,
            "touch_drag" => self.touch_drag(call.args()?).await?,
            "touch_pinch" => self.touch_pinch(call.args()?).await?,
            "rotate_screen" => self.rotate_screen(call.args()?).await?,
            other => {
                return Err(ToolError::new(
                    Code::Internal,
                    format!("browser.{other} has no motion handler"),
                ));
            }
        };
        Ok(json_result(&value))
    }

    async fn release_pointer(&self, profile_id: &str) {
        let Some(session) = self.existing_session(profile_id).await else {
            return;
        };
        let mut session = session.lock().await;
        if session.pointer_on.is_some() {
            let _ = send(&session, "Motion.destroyPointer", json!({})).await;
            session.pointer_on = None;
        }
    }

    async fn human_move(&self, a: PointArgs) -> Result<Value, ToolError> {
        let mut s = self.open(&a.profile_id, a.headless).await?;
        // A phone has no cursor: a hover menu has no touch twin, and a tap would only look like it.
        if self.is_touch(&mut s).await {
            return Err(ToolError::new(
                Code::InvalidArguments,
                "this profile is a phone and has no cursor — use touch_tap or touch_long_press",
            ));
        }
        let aim = Aim {
            selector: a.selector.as_deref(),
            x: a.x,
            y: a.y,
            offset_x: a.offset_x,
            offset_y: a.offset_y,
        };
        let t = self.point_of(&mut s, aim).await?;
        let ms = self.glide(&mut s, t).await?;
        Ok(json!({"x": t.x, "y": t.y, "duration_ms": ms}))
    }

    async fn human_click(&self, a: HumanClickArgs) -> Result<Value, ToolError> {
        in_range("click_count", a.click_count, 3)?;
        let mut s = self.open(&a.profile_id, a.headless).await?;
        let aim = Aim {
            selector: a.selector.as_deref(),
            x: a.x,
            y: a.y,
            offset_x: a.offset_x,
            offset_y: a.offset_y,
        };
        let t = self.point_of(&mut s, aim).await?;
        let label = a.selector.clone().unwrap_or_else(|| t.at());
        if !self.is_touch(&mut s).await {
            let ms = self.glide(&mut s, t).await?;
            let tap = json!({"button": a.button.unwrap_or(Button::Left), "clickCount": a.click_count.unwrap_or(1)});
            send(&s, "Motion.tap", tap).await?;
            return Ok(json!({"clicked": label, "duration_ms": ms}));
        }
        // The engine refuses a pointer on a handset: a finger instead, and a phone's context menu
        // is a long press.
        let (method, mut params) = if a.button == Some(Button::Right) {
            ("Motion.touchLongPress", json!({"x": t.x, "y": t.y}))
        } else {
            (
                "Motion.touchTap",
                json!({"x": t.x, "y": t.y, "tapCount": a.click_count.unwrap_or(1)}),
            )
        };
        if a.selector.is_some() {
            params["targetWidth"] = json!(t.width);
        }
        let r = send(&s, method, params).await?;
        Ok(json!({"tapped": label, "duration_ms": duration_ms(&r)}))
    }

    async fn human_type(&self, a: HumanTypeArgs) -> Result<Value, ToolError> {
        let mut s = self.open(&a.profile_id, a.headless).await?;
        // enterText types into the focused element; a desktop profile still wants its resting
        // cursor, which a phone refuses.
        if !self.is_touch(&mut s).await {
            self.ensure_pointer(&mut s).await?;
        }
        let typing = json!({"text": a.text, "allowTypos": a.allow_typos.unwrap_or(false)});
        let r = send(&s, "Motion.enterText", typing).await?;
        Ok(json!({"typed": a.text.chars().count(), "duration_ms": duration_ms(&r)}))
    }

    async fn human_fill(&self, a: HumanFillArgs) -> Result<Value, ToolError> {
        let mut s = self.open(&a.profile_id, a.headless).await?;
        let t = self.point_of(&mut s, Aim::element(&a.selector)).await?;
        let clear = a.clear.unwrap_or(false);
        let moved = if self.is_touch(&mut s).await {
            let tap = json!({"x": t.x, "y": t.y, "targetWidth": t.width});
            let r = send(&s, "Motion.touchTap", tap).await?;
            // A phone has no triple click: the field itself is emptied.
            if clear {
                let argv = ["fill".to_owned(), a.selector.clone(), String::new()];
                let _ = self.exec(&mut s.state, &argv).await;
            }
            duration_ms(&r)
        } else {
            let ms = self.glide(&mut s, t).await?;
            let tap = json!({"button": "left", "clickCount": if clear { 3 } else { 1 }});
            send(&s, "Motion.tap", tap).await?;
            ms
        };
        let typing = json!({"text": a.text, "allowTypos": a.allow_typos.unwrap_or(false)});
        let r = send(&s, "Motion.enterText", typing).await?;
        Ok(
            json!({"filled": a.selector, "at": t.at(), "move_ms": moved, "type_ms": duration_ms(&r)}),
        )
    }

    async fn touch_tap(&self, a: TouchTapArgs) -> Result<Value, ToolError> {
        in_range("tap_count", a.tap_count, 3)?;
        let mut s = self.open(&a.profile_id, a.headless).await?;
        self.require_touch(&mut s, "touch_tap").await?;
        let aim = Aim {
            selector: a.selector.as_deref(),
            x: a.x,
            y: a.y,
            offset_x: a.offset_x,
            offset_y: a.offset_y,
        };
        let t = self.finger_point(&mut s, aim).await?;
        let mut params = json!({"x": t.x, "y": t.y, "tapCount": a.tap_count.unwrap_or(1)});
        if let Some(w) = t.width {
            params["targetWidth"] = json!(w);
        }
        let r = send(&s, "Motion.touchTap", params).await?;
        Ok(json!({"tapped": a.selector.unwrap_or_else(|| t.at()), "duration_ms": duration_ms(&r)}))
    }

    async fn touch_long_press(&self, a: TouchLongPressArgs) -> Result<Value, ToolError> {
        let mut s = self.open(&a.profile_id, a.headless).await?;
        self.require_touch(&mut s, "touch_long_press").await?;
        let aim = Aim {
            selector: a.selector.as_deref(),
            x: a.x,
            y: a.y,
            offset_x: a.offset_x,
            offset_y: a.offset_y,
        };
        let t = self.finger_point(&mut s, aim).await?;
        let mut params = json!({"x": t.x, "y": t.y});
        if let Some(hold) = a.hold_ms {
            params["holdMs"] = json!(hold);
        }
        let r = send(&s, "Motion.touchLongPress", params).await?;
        Ok(json!({"pressed": a.selector.unwrap_or_else(|| t.at()), "duration_ms": duration_ms(&r)}))
    }

    async fn touch_swipe(&self, a: TouchSwipeArgs) -> Result<Value, ToolError> {
        let mut s = self.open(&a.profile_id, a.headless).await?;
        self.require_touch(&mut s, "touch_swipe").await?;
        let from = self
            .start_point(&mut s, a.selector.as_deref(), a.x, a.y)
            .await?;
        #[allow(clippy::cast_precision_loss)]
        let (from_x, from_y) = (from.x as f64, from.y as f64);
        let to_x = a.to_x.unwrap_or(from_x + a.dx.unwrap_or(0.0));
        let to_y = a.to_y.unwrap_or(from_y + a.dy.unwrap_or(0.0));
        #[allow(clippy::float_cmp)]
        if to_x == from_x && to_y == from_y {
            return Err(ToolError::new(
                Code::InvalidArguments,
                "a swipe of nothing goes nowhere — give dx/dy or to_x/to_y",
            ));
        }
        let mut params =
            json!({"fromX": from.x, "fromY": from.y, "toX": px(to_x), "toY": px(to_y)});
        if let Some(flick) = a.flick {
            params["flick"] = json!(flick);
        }
        let r = send(&s, "Motion.touchSwipe", params).await?;
        Ok(json!({
            "from": from.at(),
            "to": format!("{},{}", px(to_x), px(to_y)),
            "duration_ms": duration_ms(&r),
        }))
    }

    async fn touch_drag(&self, a: TouchDragArgs) -> Result<Value, ToolError> {
        let mut s = self.open(&a.profile_id, a.headless).await?;
        self.require_touch(&mut s, "touch_drag").await?;
        let from_aim = Aim {
            selector: a.selector.as_deref(),
            ..Aim::point(a.x, a.y)
        };
        let from = self.finger_point(&mut s, from_aim).await?;
        let to_aim = match &a.to_selector {
            Some(sel) => Aim::element(sel),
            None => Aim::point(a.to_x, a.to_y),
        };
        let to = self.finger_point(&mut s, to_aim).await?;
        let mut params = json!({"fromX": from.x, "fromY": from.y, "toX": to.x, "toY": to.y});
        if let Some(hold) = a.hold_ms {
            params["holdMs"] = json!(hold);
        }
        let r = send(&s, "Motion.touchDrag", params).await?;
        Ok(json!({
            "from": a.selector.unwrap_or_else(|| from.at()),
            "to": a.to_selector.unwrap_or_else(|| to.at()),
            "duration_ms": duration_ms(&r),
        }))
    }

    async fn touch_pinch(&self, a: TouchPinchArgs) -> Result<Value, ToolError> {
        if a.scale.is_nan() || a.scale <= 0.0 {
            return Err(ToolError::new(
                Code::OutOfRange,
                format!("scale must be more than 0, got {}", a.scale),
            )
            .param("scale")
            .expected("> 0"));
        }
        let mut s = self.open(&a.profile_id, a.headless).await?;
        self.require_touch(&mut s, "touch_pinch").await?;
        let at = self
            .start_point(&mut s, a.selector.as_deref(), a.x, a.y)
            .await?;
        let mut params = json!({"x": at.x, "y": at.y, "scale": a.scale});
        if let Some(rotation) = a.rotation {
            params["rotation"] = json!(rotation);
        }
        let r = send(&s, "Motion.pinch", params).await?;
        Ok(json!({"at": at.at(), "scale": a.scale, "duration_ms": duration_ms(&r)}))
    }

    async fn rotate_screen(&self, a: RotateArgs) -> Result<Value, ToolError> {
        if ![0, 90, 180, 270].contains(&a.angle) {
            return Err(ToolError::new(
                Code::InvalidEnum,
                format!("angle must be 0, 90, 180 or 270, got {}", a.angle),
            )
            .param("angle")
            .got(json!(a.angle))
            .allowed(vec![json!(0), json!(90), json!(180), json!(270)]));
        }
        let mut s = self.open(&a.profile_id, a.headless).await?;
        self.require_touch(&mut s, "rotate_screen").await?;
        let mut params = json!({"angle": a.angle});
        if let Some(turn) = a.turn_ms {
            params["turnMs"] = json!(turn);
        }
        let r = send(&s, "Motion.setOrientation", params).await?;
        Ok(json!({
            "angle": r.get("angle").cloned().unwrap_or(json!(a.angle)),
            "type": r.get("type"),
            "screen_width": r.get("screenWidth"),
            "screen_height": r.get("screenHeight"),
            "duration_ms": duration_ms(&r),
        }))
    }

    async fn open(
        &self,
        profile_id: &str,
        headless: Option<bool>,
    ) -> Result<OwnedMutexGuard<Session>, ToolError> {
        let session = self.session(profile_id, headless.unwrap_or(false)).await?;
        Ok(session.lock_owned().await)
    }

    /// Whether the page claims a touchscreen; asked once per session.
    async fn is_touch(&self, s: &mut Session) -> bool {
        if let Some(touch) = s.touch {
            return touch;
        }
        let touch = self
            .eval(&mut s.state, "navigator.maxTouchPoints > 0")
            .await
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        s.touch = Some(touch);
        touch
    }

    async fn require_touch(&self, s: &mut Session, what: &str) -> Result<(), ToolError> {
        if self.is_touch(s).await {
            return Ok(());
        }
        Err(ToolError::new(
            Code::InvalidArguments,
            format!(
                "{what} is a finger gesture and this profile has no touchscreen — start a phone profile, or use the human_* tools"
            ),
        ))
    }

    async fn viewport(&self, s: &mut Session, fallback: (f64, f64)) -> (f64, f64) {
        let size = self
            .eval(&mut s.state, "[innerWidth, innerHeight]")
            .await
            .ok();
        let dim = |i: usize| size.as_ref().and_then(|v| v.get(i)).and_then(Value::as_f64);
        match (dim(0), dim(1)) {
            (Some(width), Some(height)) => (width, height),
            _ => fallback,
        }
    }

    /// Creates the resting cursor on the active page unless it already has one. Never on the
    /// target: a glide that starts on what it aims at has no trajectory.
    async fn ensure_pointer(&self, s: &mut Session) -> Result<(), ToolError> {
        let sid = active_sid(s)?;
        if s.pointer_on.as_deref() == Some(sid.as_str()) {
            return Ok(());
        }
        let (width, height) = self.viewport(s, (1280.0, 800.0)).await;
        let rest = json!({"x": px(width * 0.15), "y": px(height * 0.8)});
        send(s, "Motion.createPointer", rest).await?;
        s.pointer_on = Some(sid);
        Ok(())
    }

    /// Moves the pointer onto `t`; the glide's duration.
    async fn glide(&self, s: &mut Session, t: Point) -> Result<Value, ToolError> {
        self.ensure_pointer(s).await?;
        let target = json!({"x": t.x, "y": t.y, "targetWidth": t.width.unwrap_or(32)});
        let r = send(s, "Motion.glideTo", target).await?;
        Ok(duration_ms(&r))
    }

    /// A selector's point (scrolled into view; its width feeds Fitts's law), or x and y.
    async fn point_of(&self, s: &mut Session, aim: Aim<'_>) -> Result<Point, ToolError> {
        if let Some(selector) = aim.selector {
            let r = self.bbox(&mut s.state, selector).await?;
            return Ok(Point {
                x: px(r.x + aim.offset_x.unwrap_or(r.width / 2.0)),
                y: px(r.y + aim.offset_y.unwrap_or(r.height / 2.0)),
                width: Some(px(r.width)),
            });
        }
        match (aim.x, aim.y) {
            (Some(x), Some(y)) => Ok(Point {
                x: px(x),
                y: px(y),
                width: Some(32),
            }),
            _ => Err(ToolError::new(
                Code::InvalidArguments,
                "give either a selector or both x and y",
            )
            .param("selector")),
        }
    }

    /// [`Self::point_of`] for a finger: the width only when an element was named, since without
    /// one the engine's own fingertip assumption is the better one.
    async fn finger_point(&self, s: &mut Session, aim: Aim<'_>) -> Result<Point, ToolError> {
        let mut p = self.point_of(s, aim).await?;
        if aim.selector.is_none() {
            p.width = None;
        }
        Ok(p)
    }

    /// The selector's or x+y's point, else the middle of the viewport.
    async fn start_point(
        &self,
        session: &mut Session,
        selector: Option<&str>,
        x: Option<f64>,
        y: Option<f64>,
    ) -> Result<Point, ToolError> {
        if selector.is_some() || (x.is_some() && y.is_some()) {
            let aim = Aim {
                selector,
                ..Aim::point(x, y)
            };
            return self.finger_point(session, aim).await;
        }
        let (width, height) = self.viewport(session, (390.0, 844.0)).await;
        Ok(Point {
            x: px(width / 2.0),
            y: px(height / 2.0),
            width: None,
        })
    }
}
