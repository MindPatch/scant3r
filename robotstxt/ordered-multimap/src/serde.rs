use serde::de::value::MapDeserializer;
use serde::de::{Deserialize, Deserializer, Error, IntoDeserializer, MapAccess, Visitor};
use serde::ser::{Serialize, SerializeMap, Serializer};

use core::fmt::{self, Formatter};
use core::hash::{BuildHasher, Hash};
use core::marker::PhantomData;

use crate::ListOrderedMultimap;

impl<K, V, S> Serialize for ListOrderedMultimap<K, V, S>
where
    K: Eq + Hash + Serialize,
    V: Serialize,
    S: BuildHasher,
{
    fn serialize<T>(&self, serializer: T) -> Result<T::Ok, T::Error>
    where
        T: Serializer,
    {
        let mut map_serializer = serializer.serialize_map(Some(self.values_len()))?;
        for (key, value) in self {
            map_serializer.serialize_entry(key, value)?;
        }
        map_serializer.end()
    }
}

struct ListOrderedMultimapVisitor<K, V, S>(PhantomData<(K, V, S)>);

impl<'de, K, V, S> Visitor<'de> for ListOrderedMultimapVisitor<K, V, S>
where
    K: Deserialize<'de> + Eq + Hash,
    V: Deserialize<'de>,
    S: BuildHasher + Default,
{
    type Value = ListOrderedMultimap<K, V, S>;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "a map")
    }

    fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut map = ListOrderedMultimap::with_capacity_and_hasher(
            access.size_hint().unwrap_or_default(),
            access.size_hint().unwrap_or_default(),
            S::default(),
        );
        while let Some((key, value)) = access.next_entry()? {
            map.append(key, value);
        }
        Ok(map)
    }
}

impl<'de, K, V, S> Deserialize<'de> for ListOrderedMultimap<K, V, S>
where
    K: Deserialize<'de> + Eq + Hash,
    V: Deserialize<'de>,
    S: BuildHasher + Default,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(ListOrderedMultimapVisitor(PhantomData))
    }
}

impl<'de, K, V, S, E> IntoDeserializer<'de, E> for ListOrderedMultimap<K, V, S>
where
    K: Clone + Eq + Hash + IntoDeserializer<'de, E>,
    V: IntoDeserializer<'de, E>,
    S: BuildHasher,
    E: Error,
{
    type Deserializer = MapDeserializer<'de, <Self as IntoIterator>::IntoIter, E>;

    fn into_deserializer(self) -> Self::Deserializer {
        MapDeserializer::new(self.into_iter())
    }
}
