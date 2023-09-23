use crate::query::{Query, UpdateQuery};
use crate::types::DbType;

use std::io::{Read, Write};

use std::hash::Hash;
use std::collections::HashMap;

pub trait TableLayout: std::fmt::Debug + Eq + Hash {
    fn serialize(&self, w: &mut dyn Write) -> std::io::Result<()>;
    fn deserialize(r: &mut dyn Read) -> std::io::Result<Self>
    where
        Self: Sized;
}

impl<A: DbType + std::fmt::Debug> TableLayout for A {
    fn serialize(&self, w: &mut dyn Write) -> std::io::Result<()> {
        self.serialize(w)
    }

    fn deserialize(r: &mut dyn Read) -> std::io::Result<Self> {
        A::deserialize(r)
    }
}

impl<A: TableLayout, B: TableLayout> TableLayout for (A, B) {
    fn serialize(&self, w: &mut dyn Write) -> std::io::Result<()> {
        self.1.serialize(w)?;
        self.0.serialize(w)
    }

    fn deserialize(r: &mut dyn Read) -> std::io::Result<Self> {
        Ok((A::deserialize(r)?, B::deserialize(r)?))
    }
}

pub struct DbTable<T: TableLayout, U: Clone + Eq + Hash, P: Fn(&T) -> &U> {
    entries: HashMap<U, T>,
    primary: P,
}

pub struct TableQuery<'a, T: TableLayout, U: Clone + Eq>(std::collections::hash_map::Iter<'a, U, T>);

impl<T: TableLayout, U: Clone + Eq + Hash, K: Fn(&T) -> &U> DbTable<T, U, K> {
    pub fn new(primary: K) -> Self {
        DbTable {
            entries: Default::default(),
            primary,
        }
    }

	pub fn query(&self) -> TableQuery<T, U> {
		TableQuery(self.entries.iter())
	}

    pub fn can_insert(&mut self, t: &T) -> bool {
        self.entries.get((self.primary)(t)).is_none()
    }

    pub fn insert(&mut self, t: T) {
        self.entries.insert((self.primary)(&t).clone(), t);
    }
}

impl<'a, T: TableLayout, Q: Clone + Eq + Hash> Query for TableQuery<'a, T, Q> {
    type Input = &'a T;
    fn query<U, P: Fn(Self::Input) -> Option<U>>(&mut self, pred: P) -> Option<U> {
		while let Some(e) = self.0.next() {
			if let Some(x) = pred(e.1) {
				return Some(x);
			}
		}
		None
    }
}

impl<'a, T: TableLayout, U: Clone + Eq + Hash, K: Fn(&T) -> &U> UpdateQuery<T>
    for &'a mut DbTable<T, U, K>
{
    fn set<F: FnMut(&mut T) -> bool>(&mut self, mut pred: F) {
        for (_, entry) in &mut self.entries {
            pred(entry);
        }
    }
}
