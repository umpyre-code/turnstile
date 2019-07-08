use crate::models;

pub trait Message {
    fn is_valid(&self) -> bool;
}

impl models::Message {
    pub fn is_valid(&self) -> bool {
        println!("running validator");
        true
    }
}
