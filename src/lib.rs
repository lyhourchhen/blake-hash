use napi::bindgen_prelude::*;
use napi_derive::napi;

#[cfg(all(
  not(debug_assertions),
  not(all(target_os = "windows", target_arch = "aarch64")),
  not(all(target_os = "linux", target_arch = "aarch64", target_env = "musl")),
))]
#[global_allocator]
static ALLOC: mimalloc_rust::GlobalMiMalloc = mimalloc_rust::GlobalMiMalloc;

macro_rules! impl_hasher {
  ($name:ident, $algorithm:expr) => {
    #[napi]
    impl $name {
      #[napi(constructor)]
      pub fn new() -> Self {
        Self($algorithm)
      }

      #[napi]
      pub fn update(&mut self, input: Either3<String, Buffer, f64>) -> Result<()> {
        match input {
          Either3::A(a) => {
            self.0.update(a.as_bytes());
          }
          Either3::B(b) => {
            self.0.update(b.as_ref());
          }
          Either3::C(c) => {
            let mut buffer = ryu::Buffer::new();
            self.0.update(buffer.format_finite(c).as_bytes());
          }
        }
        Ok(())
      }

      #[napi]
      pub fn digest(&mut self, format: Option<String>) -> Result<String> {
        match format.unwrap_or_else(|| "hex".to_owned()).as_str() {
          "hex" => Ok(self.0.finalize().to_hex().to_string()),
          "base64" => Ok(base64::encode(self.0.finalize().as_ref())),
          "base64-url-safe" => Ok(base64::encode_config(
            self.0.finalize().as_ref(),
            base64::URL_SAFE,
          )),
          _ => Err(Error::new(Status::InvalidArg, "Invalid format".to_owned())),
        }
      }

      #[napi]
      pub fn digest_buffer(&mut self) -> Buffer {
        self.0.finalize().as_ref().into()
      }
    }
  };
}

#[napi]
#[repr(transparent)]
struct Blake2bHasher(blake2b_simd::State);

#[napi]
#[repr(transparent)]
struct Blake2sHasher(blake2s_simd::State);

impl_hasher!(Blake2bHasher, blake2b_simd::State::new());
impl_hasher!(Blake2sHasher, blake2s_simd::State::new());

#[napi]
#[repr(transparent)]
struct Blake3Hasher(blake3::Hasher);

#[napi]
impl Blake3Hasher {
  #[inline]
  #[napi(constructor)]
  pub fn new() -> Self {
    Self(blake3::Hasher::new())
  }

  #[napi]
  pub fn update(&mut self, input: Either3<String, Buffer, f64>) -> Result<()> {
    match input {
      Either3::A(a) => {
        self.0.update(a.as_bytes());
      }
      Either3::B(b) => {
        self.0.update(b.as_ref());
      }
      Either3::C(c) => {
        let mut buffer = ryu::Buffer::new();
        self.0.update(buffer.format_finite(c).as_bytes());
      }
    }
    Ok(())
  }

  #[napi]
  #[inline]
  pub fn digest(&mut self, format: Option<String>) -> Result<String> {
    match format.unwrap_or_else(|| "hex".to_owned()).as_str() {
      "hex" => Ok(self.0.finalize().to_hex().to_string()),
      "base64" => Ok(base64::encode(self.0.finalize().as_bytes())),
      "base64-url-safe" => Ok(base64::encode_config(
        self.0.finalize().as_bytes(),
        base64::URL_SAFE,
      )),
      _ => Err(Error::new(Status::InvalidArg, "Invalid format".to_owned())),
    }
  }

  #[napi]
  #[inline]
  pub fn digest_buffer(&mut self) -> Buffer {
    self.0.finalize().as_bytes().to_vec().into()
  }
}
