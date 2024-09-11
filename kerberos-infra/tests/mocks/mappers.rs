use std::collections::HashMap;

use rand::Rng;

pub struct Mapper {
    rule: HashMap<String, String>,
}

impl Mapper {
    pub fn prepare() -> Self {
        let mut rule = HashMap::new();
        let data = [
            ("Hello AS Server", "Response Back There"),
            ("What's up TGT?", "I'm fine, thank you"),
            ("123283823", "123283823"),
        ];
        for (key, value) in data.iter() {
            rule.insert(key.to_string(), value.to_string());
        }
        Mapper { rule }
    }

    pub fn random(&self) -> &str {
        let keys = self.rule.keys().collect::<Vec<&String>>();
        let mut rng = rand::thread_rng();
        let index = rng.gen_range(0..keys.len());
        keys[index]
    }
}
