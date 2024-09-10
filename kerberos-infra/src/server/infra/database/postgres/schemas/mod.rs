pub struct Schemas;

impl Schemas {
    pub fn to_string(&self) -> String {
        let script = r#"
            CREATE TABLE IF NOT EXISTS my_table (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        "#;
        
        script.to_string()
    }
}
