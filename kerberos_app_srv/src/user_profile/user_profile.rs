use chrono::{Date, DateTime};
use serde::Serialize;

#[derive(Serialize)]
pub struct UserProfile {
    pub id: i32,
    pub username: String,
    pub email: String,
    pub firstname: String,
    pub lastname: String,
    pub birthday: DateTime<chrono::Utc>,
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
}
