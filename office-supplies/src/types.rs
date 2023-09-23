use sha2::{Digest, Sha256};
use std::io::{Read, Write};

pub trait DbType: Eq + std::hash::Hash {
    fn set(&mut self, data: &Self);

    fn serialize(&self, w: &mut dyn Write) -> std::io::Result<()>;
    fn deserialize(r: &mut dyn Read) -> std::io::Result<Self>
    where
        Self: Sized;
}

impl DbType for i64 {
    fn set(&mut self, data: &Self) {
        *self = *data;
    }

    fn serialize(&self, w: &mut dyn Write) -> std::io::Result<()> {
        w.write_all(&self.to_be_bytes())?;
        Ok(())
    }

    fn deserialize(r: &mut dyn Read) -> std::io::Result<Self> {
        let mut data = [0u8; 8];
        r.read_exact(&mut data)?;
        Ok(i64::from_be_bytes(data))
    }
}

fn hex(data: &[u8; 32], mut output: &mut [u8]) {
    for d in data {
        unsafe {
            char::from_digit((d >> 4) as u32, 16)
                .unwrap_unchecked()
                .encode_utf8(output);
            char::from_digit((d & 15) as u32, 16)
                .unwrap_unchecked()
                .encode_utf8(&mut output[1..]);
            output = &mut output[2..]
        }
    }
}

impl DbType for Box<[u8]> {
    fn set(&mut self, data: &Self) {
        unsafe {
            let data = data.as_ref();
            *self = Box::from_raw(std::slice::from_raw_parts_mut(
                data.as_ptr() as *mut _,
                data.len(),
            ));
        }
    }

    fn serialize(&self, w: &mut dyn Write) -> std::io::Result<()> {
        let mut blobid = [0u8; 32];
        blobid.copy_from_slice(&Sha256::digest(self));

        unsafe {
            let mut path = [0u8; 13 + 64];
            let (dir, filename) = path.split_at_mut(13);
            dir.copy_from_slice(b"data/objects/");
            hex(&blobid, filename);

            use std::fs::File;
            match File::options()
                .write(true)
                .create_new(true)
                .open(std::str::from_utf8_unchecked(&path))
            {
                Ok(mut handle) => {
                    handle.write_all(self)?;
                }
                // Filename is based upon content hash
                // If it already exists, then the exact same contents are already on disk
                // => File Deduplication
                // But we need to update the modified time or else it will be garbage collected too early
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    File::options()
                        .append(true)
                        .open(std::str::from_utf8_unchecked(&path))?;
                }
                Err(e) => return Err(e),
            };
        }

        w.write_all(&blobid)?;
        Ok(())
    }

    fn deserialize(r: &mut dyn Read) -> std::io::Result<Self> {
        let mut blobid = [0u8; 32];
        r.read_exact(&mut blobid)?;

        let mut path = [0u8; 13 + 64];
        let (dir, filename) = path.split_at_mut(13);
        dir.copy_from_slice(b"data/objects/");
        hex(&blobid, filename);

        unsafe {
            let data = std::fs::read(std::str::from_utf8_unchecked(&path))?.into_boxed_slice();

            // Check for file corruption
            use std::ops::Deref;
            if Sha256::digest(&data).deref() != &blobid[..] {
				// Remove corrupted file
                std::fs::remove_file(std::str::from_utf8_unchecked(&path))?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Not Found",
                ));
            }

            Ok(data)
        }
    }
}

impl DbType for String {
    fn set(&mut self, data: &Self) {
        unsafe {
            *self = String::from_raw_parts(data.as_ptr() as *mut _, data.len(), data.capacity());
        }
    }

    fn serialize(&self, w: &mut dyn Write) -> std::io::Result<()> {
        let bytes = self.as_bytes();
        w.write_all(bytes)?;
        w.write_all(&bytes.len().to_be_bytes())?;
        Ok(())
    }

    fn deserialize(r: &mut dyn Read) -> std::io::Result<Self> {
        let mut len = [0u8; 8];
        r.read_exact(&mut len)?;
        let len = usize::from_be_bytes(len);
        if len > 8192 {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        }

        let mut data = Vec::new();
        data.resize(len, 0);
        r.read_exact(&mut data[..])?;
        Ok(String::from_utf8(data).expect("Invalid UTF-8"))
    }
}
