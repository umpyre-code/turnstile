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
        "reason": "Unprocessable Entity. The request was well-formed but was unable to be followed due to semantic errors."
    })
}

#[catch(401)]
pub fn unauthorized() -> JsonValue {
    json!({
        "status": "error",
        "reason": "Unauthorized."
    })
}
