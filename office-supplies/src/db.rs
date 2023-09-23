use crate::tables::{DbTable, TableLayout};
use crate::query::UpdateQuery;

use std::io::{Cursor, Error, ErrorKind, Read, Seek, SeekFrom, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use std::fs::File;
use std::path::Path;
use std::os::unix::fs::OpenOptionsExt;

use std::ops::{Deref, DerefMut};
use std::hash::Hash;

struct DatabaseHandle(File, Cursor<&'static mut [u8]>);

impl DatabaseHandle {
    fn check_signature(&mut self) -> std::io::Result<()> {
        let mut sig = [0u8; 2];
        match self.0.read(&mut sig)? {
            0 => {
                self.write_all(&[0xdb, 0x42])?;
                self.sync_data()?;
            }
            2 if sig == [0xdb, 0x42] => (),
            _ => panic!("Not a valid database..."),
        };
        Ok(())
    }

    fn write_record<T: TableLayout>(&mut self, t: &T) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
		self.1.seek(SeekFrom::Start(0)).expect("Failed to seek internal memory buffer");
        t.serialize(&mut self.1)
            .expect("BUG: Could not serialize to internal memory buffer");
        self.1.write_all(&timestamp.to_be_bytes())
            .expect("BUG: Could not serialize to internal memory buffer");
		let length = self.1.position() as usize;
		
		let pos = self.0.seek(SeekFrom::End(0)).expect("Unable to read file length");
		if let Err(_) = self.0.write_all(&self.1.get_ref()[..length]) {
			self.0.set_len(pos).expect("Failed to undo failed write operation. The database is probably fucked, good luck lol");
			panic!("Could not write database row to disk");
		}
        self.sync_data().expect("Failed to sync database to disk");
    }
}

impl Read for DatabaseHandle {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
		// Read file backwards (this makes it more resilient against database corruptions)
		let pos = self.stream_position()?;
        self.seek(SeekFrom::Current(-(buf.len() as i64)))?;
        if self.stream_position()? < 2 {
			self.seek(SeekFrom::Start(pos))?;
            return Err(Error::from(ErrorKind::UnexpectedEof));
        }
		
		let pos = self.stream_position()?;
        self.deref_mut().read_exact(buf)?;
		self.seek(SeekFrom::Start(pos))?;
        Ok(buf.len())
    }
}

impl Deref for DatabaseHandle {
    type Target = File;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for DatabaseHandle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub struct Database<T: TableLayout, U: Clone + Eq + Hash, P: Fn(&T) -> &U> {
    handle: DatabaseHandle,
    table: DbTable<T, U, P>,
}

impl<T: TableLayout, U: Clone + Eq + Hash, K: Fn(&T) -> &U> Database<T, U, K> {
	fn parse(handle: &mut DatabaseHandle) -> std::io::Result<(u64, T)> {
		let mut time = [0u8; 8];
		handle.read_exact(&mut time)?;
		let data = T::deserialize(handle)?;
		Ok((u64::from_be_bytes(time), data))
	}

	fn generate_mem_buffer() -> &'static mut [u8] {
		let mut v = Vec::with_capacity(16384);
		v.resize(16384, 0u8);
		Box::leak(v.into_boxed_slice())
	}

	fn from_handle(mut handle: DatabaseHandle, primary: K) -> std::io::Result<Self> {
        // Check that it's a valid database file
        handle.check_signature()?;

        // Now, read the entries (backwards for more resilience)
        handle.seek(SeekFrom::End(0))?;

        let current = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut table = DbTable::<T, U, K>::new(primary);
        while let Ok((timestamp, entry)) = Self::parse(&mut handle) {
			if timestamp < current - 20 * 60 {
				break;
			}
			if table.can_insert(&entry) {
				table.insert(entry);
			}
        }
        Ok(Database { handle, table })
	}
	
    pub fn new<P: AsRef<Path>>(filename: P, primary: K) -> std::io::Result<Self> {
        let handle = DatabaseHandle(
            File::options()
                .read(true)
                .append(true)
                .create(true)
				.mode(0o644)
                .open(filename)?,
			Cursor::new(Self::generate_mem_buffer())
        );
		Self::from_handle(handle, primary)
    }

	pub fn new_readonly<P: AsRef<Path>>(filename: P, primary: K) -> std::io::Result<Self> {
        let handle = DatabaseHandle(
            File::options()
                .read(true)
                .open(filename)?,
			Cursor::new(Self::generate_mem_buffer())
        );
		Self::from_handle(handle, primary)
    }

    pub fn insert(&mut self, t: T) -> bool {
        if self.table.can_insert(&t) {
            self.handle.write_record(&t);
            self.table.insert(t);
            true
        } else {
            false
        }
    }

    pub fn update<'a>(&'a mut self) -> UpdateQueryImpl<'a, T, U, K> {
        UpdateQueryImpl(self)
    }
}

pub struct UpdateQueryImpl<'a, T: TableLayout, U: Clone + Eq + Hash, K: Fn(&T) -> &U>(
    pub &'a mut Database<T, U, K>,
);

impl<'a, T: TableLayout + Clone, U: Clone + Eq + Hash, K: Fn(&T) -> &U> UpdateQuery<T>
    for UpdateQueryImpl<'a, T, U, K>
{
    fn set<F: FnMut(&mut T) -> bool>(&mut self, mut pred: F) {
        <&'_ mut DbTable<T, U, K> as UpdateQuery<T>>::set(&mut &mut self.0.table, |x| {
            if pred(x) {
                self.0.handle.write_record(x);
                true
            } else {
                false
            }
        });
    }
}

impl<T: TableLayout, U: Clone + Eq + Hash, P: Fn(&T) -> &U> Deref
    for Database<T, U, P>
{
    type Target = DbTable<T, U, P>;

    fn deref(&self) -> &Self::Target {
        &self.table
    }
}

impl<T: TableLayout, U: Clone + Eq + Hash, P: Fn(&T) -> &U> DerefMut
    for Database<T, U, P>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.table
    }
}
