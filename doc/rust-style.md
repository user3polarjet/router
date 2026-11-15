# Rust style

1. No comments in code.
2. No local imports (`use` inside the code, or at the top of a file) except for traits. Write full paths
   (`tokio::net::UdpSocket`).
3. Data-oriented: plain structs and enums, free functions over the data, no boilerplate and no wrapper types
   that only forward calls.
4. No tests are written for new code.
5. Prefer enums to traits and generics.
