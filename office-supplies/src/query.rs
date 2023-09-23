use crate::tables::TableLayout;

pub trait Query {
    type Input;
    fn query<U, P: Fn(Self::Input) -> Option<U>>(&mut self, pred: P) -> Option<U>;

	fn execute(self) -> QueryIterator<Self>
    where
        Self: Sized,
	{
		QueryIterator(self)
	}

    fn select<U, P: Fn(Self::Input) -> U>(self, pred: P) -> SelectQuery<Self, U, P>
    where
        Self: Sized,
    {
        SelectQuery(self, pred)
    }

    fn filter<P: Fn(&'_ Self::Input) -> bool>(self, pred: P) -> WhereQuery<Self, P>
    where
        Self: Sized,
    {
        WhereQuery(self, pred)
    }
}

pub struct QueryIterator<T: Query>(T);

impl<T: Query> Iterator for QueryIterator<T> {
	type Item = T::Input;
	fn next(&mut self) -> Option<Self::Item> {
		self.0.query(|x| Some(x))
	}
}

pub trait UpdateQuery<T: TableLayout> {
    fn set<P: FnMut(&mut T) -> bool>(&mut self, pred: P);

	fn execute<F: FnMut(&mut T)>(&mut self, mut pred: F) {
		self.set(|t| {
			pred(t);
			true
		})
	}

    fn when<P: Fn(&T) -> bool>(self, pred: P) -> WhenQuery<T, Self, P>
    where
        Self: Sized,
    {
        WhenQuery(self, pred, Default::default())
    }
}

pub struct SelectQuery<Q: Query, V, P: Fn(Q::Input) -> V>(Q, P);

impl<Q: Query, V, P1: Fn(Q::Input) -> V> Query for SelectQuery<Q, V, P1> {
    type Input = V;
    fn query<U, P2: Fn(Self::Input) -> Option<U>>(&mut self, pred: P2) -> Option<U> {
        self.0.query(|x| pred(self.1(x)))
    }
}

pub struct WhereQuery<Q: Query, P: Fn(&'_ Q::Input) -> bool>(Q, P);

impl<Q: Query, P1: Fn(&'_ Q::Input) -> bool> Query for WhereQuery<Q, P1> {
    type Input = Q::Input;
    fn query<U, P2: Fn(Self::Input) -> Option<U>>(&mut self, pred: P2) -> Option<U> {
        self.0.query(|x| if self.1(&x) { pred(x) } else { None })
    }
}

pub struct WhenQuery<T: TableLayout, Q: UpdateQuery<T>, P: Fn(&'_ T) -> bool>(
    Q,
    P,
    std::marker::PhantomData<T>,
);

impl<T: TableLayout, Q: UpdateQuery<T>, P: Fn(&'_ T) -> bool> UpdateQuery<T>
    for WhenQuery<T, Q, P>
{
    fn set<F: FnMut(&mut T) -> bool>(&mut self, mut pred: F) {
        self.0.set(|x| {
            if (self.1)(x) {
                pred(x)
            } else {
				false
			}
        });
    }
}
