pub struct TicketPolicy {
    pub realm: String,
    pub max_ticket_lifetime: u64,
    pub max_renewable_lifetime: u64,
    pub minimum_ticket_lifetime: u64,
}