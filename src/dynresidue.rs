//! the minimal required implementation to use [`DynResidue`] as a share value/identifier
//!
//! this entire implementation may be extremely terrible because for some things (like [`WrappedDynResidue::ZERO`]) it
//! just can't know the correct modulus so moduli are copied on operations.
//! do not even try to use this with different moduli, things *will* absolutely be fucked up. but it works.

use std::ops::{Add, AddAssign, Deref, DerefMut, Mul, MulAssign, Sub, SubAssign};

use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    ArrayEncoding, CheckedAdd, CheckedMul, CheckedSub, Encoding, Invert, Random, Uint, Zero,
};
use vsss_rs::{ShareElement, ShareIdentifier, VsssResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrappedDynResidue<const LIMBS: usize> {
    Residue(DynResidue<LIMBS>),
    Integer(Uint<LIMBS>),
}
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IdentifierDynResidue<const LIMBS: usize>(pub WrappedDynResidue<LIMBS>);

impl<const LIMBS: usize> WrappedDynResidue<LIMBS> {
    pub const ZERO: Self = Self::Integer(Uint::ZERO);
    pub const ONE: Self = Self::Integer(Uint::ONE);

    pub fn sub(&self, rhs: &Self) -> Self {
        match (self, rhs) {
            (Self::Residue(res0), Self::Residue(res1)) => Self::Residue(res0 - res1),
            (Self::Residue(res), Self::Integer(int)) => {
                Self::Residue(res - DynResidue::new(int, *res.params()))
            }
            (Self::Integer(int), Self::Residue(res)) => {
                Self::Residue(DynResidue::new(&int, *res.params()) - res)
            }
            (Self::Integer(int0), Self::Integer(int1)) => {
                Self::Integer(int0.checked_sub(int1).unwrap())
            }
        }
    }

    pub fn add(&self, rhs: &Self) -> Self {
        match (self, rhs) {
            (Self::Residue(res0), Self::Residue(res1)) => Self::Residue(res0 + res1),
            (Self::Residue(res), Self::Integer(int)) => {
                Self::Residue(res + DynResidue::new(int, *res.params()))
            }
            (Self::Integer(int), Self::Residue(res)) => {
                Self::Residue(DynResidue::new(&int, *res.params()) + res)
            }
            (Self::Integer(int0), Self::Integer(int1)) => {
                Self::Integer(int0.checked_add(int1).unwrap())
            }
        }
    }

    pub fn mul(&self, rhs: &Self) -> Self {
        match (self, rhs) {
            (Self::Residue(res0), Self::Residue(res1)) => Self::Residue(res0 * res1),
            (Self::Residue(res), Self::Integer(int)) => {
                Self::Residue(res * DynResidue::new(int, *res.params()))
            }
            (Self::Integer(int), Self::Residue(res)) => {
                Self::Residue(DynResidue::new(&int, *res.params()) * res)
            }
            (Self::Integer(int0), Self::Integer(int1)) => {
                Self::Integer(int0.checked_mul(int1).unwrap())
            }
        }
    }

    pub fn is_zero(&self) -> vsss_rs::subtle::Choice {
        match self {
            Self::Integer(int) => int.is_zero(),
            // this does not need retrieval because the montgomery form of zero is zero
            Self::Residue(res) => res.as_montgomery().is_zero(),
        }
    }

    pub fn invert(&self) -> Option<Self> {
        match self {
            Self::Residue(res) => {
                let val = Invert::invert(res);
                val.into_option().map(Self::Residue)
            }
            Self::Integer(_) => None,
        }
    }

    pub fn retrieve(&self) -> Uint<LIMBS> {
        match self {
            Self::Residue(res) => res.retrieve(),
            Self::Integer(int) => *int,
        }
    }
}

impl<const LIMBS: usize> IdentifierDynResidue<LIMBS> {
    pub const fn new(integer: &Uint<LIMBS>, residue_params: DynResidueParams<LIMBS>) -> Self {
        Self(WrappedDynResidue::Residue(DynResidue::new(
            integer,
            residue_params,
        )))
    }
}

impl<const LIMBS: usize> Default for WrappedDynResidue<LIMBS> {
    fn default() -> Self {
        Self::ZERO
    }
}

impl<const LIMBS: usize> Sub for WrappedDynResidue<LIMBS> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self::sub(&self, &rhs)
    }
}

impl<const LIMBS: usize> Sub<&Self> for WrappedDynResidue<LIMBS> {
    type Output = Self;
    fn sub(self, rhs: &Self) -> Self::Output {
        Self::sub(&self, rhs)
    }
}

impl<const LIMBS: usize> SubAssign for WrappedDynResidue<LIMBS> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = Self::sub(&self, &rhs);
    }
}

impl<const LIMBS: usize> SubAssign<&Self> for WrappedDynResidue<LIMBS> {
    fn sub_assign(&mut self, rhs: &Self) {
        *self = Self::sub(&self, rhs);
    }
}

impl<const LIMBS: usize> Add for WrappedDynResidue<LIMBS> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self::add(&self, &rhs)
    }
}

impl<const LIMBS: usize> Add<&Self> for WrappedDynResidue<LIMBS> {
    type Output = Self;
    fn add(self, rhs: &Self) -> Self::Output {
        Self::add(&self, rhs)
    }
}

impl<const LIMBS: usize> AddAssign for WrappedDynResidue<LIMBS> {
    fn add_assign(&mut self, rhs: Self) {
        *self = Self::add(&self, &rhs);
    }
}

impl<const LIMBS: usize> AddAssign<&Self> for WrappedDynResidue<LIMBS> {
    fn add_assign(&mut self, rhs: &Self) {
        *self = Self::add(&self, rhs);
    }
}

impl<const LIMBS: usize> Mul for WrappedDynResidue<LIMBS> {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        Self::mul(&self, &rhs)
    }
}

impl<const LIMBS: usize> Mul<&Self> for WrappedDynResidue<LIMBS> {
    type Output = Self;
    fn mul(self, rhs: &Self) -> Self::Output {
        Self::mul(&self, rhs)
    }
}

impl<const LIMBS: usize> MulAssign for WrappedDynResidue<LIMBS> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = Self::mul(&self, &rhs)
    }
}

impl<const LIMBS: usize> MulAssign<&Self> for WrappedDynResidue<LIMBS> {
    fn mul_assign(&mut self, rhs: &Self) {
        *self = Self::mul(&self, rhs)
    }
}

impl<const LIMBS: usize> Deref for IdentifierDynResidue<LIMBS> {
    type Target = WrappedDynResidue<LIMBS>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LIMBS: usize> DerefMut for IdentifierDynResidue<LIMBS> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const LIMBS: usize> AsRef<WrappedDynResidue<LIMBS>> for IdentifierDynResidue<LIMBS> {
    fn as_ref(&self) -> &WrappedDynResidue<LIMBS> {
        self
    }
}

impl<const LIMBS: usize> AsMut<WrappedDynResidue<LIMBS>> for IdentifierDynResidue<LIMBS> {
    fn as_mut(&mut self) -> &mut WrappedDynResidue<LIMBS> {
        self
    }
}

impl<const LIMBS: usize> From<WrappedDynResidue<LIMBS>> for IdentifierDynResidue<LIMBS> {
    fn from(value: WrappedDynResidue<LIMBS>) -> Self {
        Self(value)
    }
}

impl<const LIMBS: usize> From<DynResidue<LIMBS>> for IdentifierDynResidue<LIMBS> {
    fn from(value: DynResidue<LIMBS>) -> Self {
        Self(WrappedDynResidue::Residue(value))
    }
}

impl<const LIMBS: usize> From<&Self> for IdentifierDynResidue<LIMBS> {
    fn from(value: &Self) -> Self {
        Self(value.0)
    }
}

impl<const LIMBS: usize> Mul<&Self> for IdentifierDynResidue<LIMBS> {
    type Output = Self;
    fn mul(self, rhs: &Self) -> Self::Output {
        Self(self.0.mul(rhs.0))
    }
}

impl<const LIMBS: usize> ShareElement for IdentifierDynResidue<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    type Inner = WrappedDynResidue<LIMBS>;
    type Serialization = <Uint<LIMBS> as Encoding>::Repr;

    fn zero() -> Self {
        Self(Self::Inner::ZERO)
    }

    fn one() -> Self {
        Self(Self::Inner::ONE)
    }

    fn is_zero(&self) -> vsss_rs::subtle::Choice {
        self.0.is_zero()
    }

    fn serialize(&self) -> Self::Serialization {
        self.retrieve().to_be_bytes()
    }

    fn deserialize(_serialized: &Self::Serialization) -> VsssResult<Self> {
        Err(vsss_rs::Error::NotImplemented)
    }

    fn from_slice(_slice: &[u8]) -> VsssResult<Self> {
        Err(vsss_rs::Error::NotImplemented)
    }

    fn to_vec(&self) -> Vec<u8> {
        self.serialize().as_ref().to_vec()
    }

    fn random(mut rng: impl rand::RngCore + rand::CryptoRng) -> Self {
        let rand = Uint::<LIMBS>::random(&mut rng);
        Self(WrappedDynResidue::Integer(rand))
    }
}

impl<const LIMBS: usize> ShareIdentifier for IdentifierDynResidue<LIMBS>
where
    Uint<LIMBS>: ArrayEncoding,
{
    fn inc(&mut self, increment: &Self) {
        self.0 += increment.0
    }

    fn invert(&self) -> VsssResult<Self> {
        self.0
            .invert()
            .map_or(Err(vsss_rs::Error::NotImplemented), |v| Ok(Self(v)))
    }
}
