use rocket_contrib::json::JsonValue;

#[catch(404)]
pub fn not_found() -> JsonValue {
    json!({
        "status": "error",
        "reason": "Resource was not found."
    })
}

#[catch(422)]
pub fn unprocessable_entity() -> JsonValue {
    json!({
        "status": "error",
        "reason": "Unprocessable entity. The request was well-formed but was unable to be followed due to semantic errors."
    })
}

#[catch(401)]
pub fn unauthorized() -> JsonValue {
    json!({
        "status": "error",
        "reason": "Unauthorized."
    })
}

#[catch(429)]
pub fn too_many_requests() -> JsonValue {
    json!({
        "status": "error",
        "reason": "Too many requests."
    })
}

#[catch(400)]
pub fn bad_request() -> JsonValue {
    json!({
        "status": "error",
        "reason": "Bad request."
    })
}
