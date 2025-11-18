use crate::{common::Error, concolic::Solver};
use std::collections::HashSet;
use z3::{
    ast::{Array, Ast, AstKind, Bool, Dynamic, Float, Int, BV},
    Sort, Symbol,
};

#[allow(unused)]
#[derive(Debug, Clone)]
pub enum ArrayInfo {
    Int { elem_size: u64, elem_cnt: u64 },
    FP { is_double: bool, elem_cnt: u64 },
}

#[derive(Debug, Clone)]
pub enum TranslationEntry<'ctx, T: Clone> {
    Scalar {
        expr: T,
        depth: usize,
        coerced_values: HashSet<Dynamic<'ctx>>,
        phantom: std::marker::PhantomData<&'ctx ()>,
    },
    Array {
        expr: T,
        depth: usize,
        coerced_values: HashSet<Dynamic<'ctx>>,
        array_info: ArrayInfo,
        phantom: std::marker::PhantomData<&'ctx ()>,
    },
}

impl<'ctx, T> TranslationEntry<'ctx, T>
where
    T: Into<Dynamic<'ctx>> + Clone + ToString,
{
    /// Only creates non array entries.
    pub fn new_scalar(expr: T, depth: usize, coerced_values: HashSet<Dynamic<'ctx>>) -> Self {
        validate_coerced_values(&expr, &coerced_values);
        Self::Scalar {
            expr,
            depth,
            coerced_values,
            phantom: std::marker::PhantomData,
        }
    }

    pub fn new_array(
        expr: T,
        depth: usize,
        coerced_values: HashSet<Dynamic<'ctx>>,
        array_info: ArrayInfo,
    ) -> Self {
        validate_coerced_values(&expr, &coerced_values);
        Self::Array {
            expr,
            depth,
            coerced_values,
            array_info,
            phantom: std::marker::PhantomData,
        }
    }

    pub fn coerced_values(&self) -> &HashSet<Dynamic<'ctx>> {
        match self {
            TranslationEntry::Scalar { coerced_values, .. } => coerced_values,
            TranslationEntry::Array { coerced_values, .. } => coerced_values,
        }
    }

    pub fn expr(&self) -> &T {
        match self {
            TranslationEntry::Scalar { expr, .. } => expr,
            TranslationEntry::Array { expr, .. } => expr,
        }
    }

    pub fn depth(&self) -> usize {
        match self {
            TranslationEntry::Scalar { depth, .. } => *depth,
            TranslationEntry::Array { depth, .. } => *depth,
        }
    }

    pub fn array_info(&self) -> Option<&ArrayInfo> {
        match self {
            TranslationEntry::Scalar { .. } => None,
            TranslationEntry::Array { array_info, .. } => Some(array_info),
        }
    }
}

fn validate_coerced_values<'ctx, T: Into<Dynamic<'ctx>> + Clone + ToString>(
    expr: &T,
    coerced_values: &HashSet<Dynamic<'ctx>>,
) {
    let const_apps = Solver::gather_const_apps(expr.clone().into());
    if !coerced_values.is_subset(&const_apps) {
        panic!(
            "Invalid coerced values {:?}: {:?} / const_apps: {:?}",
            expr.to_string(),
            coerced_values,
            const_apps
        );
    }
}

#[allow(unused)]
impl<'ctx> TranslationEntry<'ctx, Dynamic<'ctx>> {
    pub fn _eq(&self, other: &Self) -> TranslationEntry<'ctx, Bool<'ctx>> {
        let expr = self.expr()._eq(other.expr());
        let coerced_values = self
            .coerced_values()
            .union(other.coerced_values())
            .into_iter()
            .map(|x| x.to_owned())
            .collect();
        TranslationEntry::new_scalar(
            expr,
            usize::max(self.depth(), other.depth()) + 1,
            coerced_values,
        )
    }

    const EXPR_TO_STRING_MAX_DEPTH: usize = 20;
    pub fn to_string(&self) -> Result<String, Error> {
        if self.depth() > Self::EXPR_TO_STRING_MAX_DEPTH {
            return Ok("...".to_string());
        } else {
            let expr_string = self.expr().to_string();
            Ok(expr_string)
        }
    }

    pub fn as_bool(&self) -> Option<TranslationEntry<'ctx, Bool<'ctx>>> {
        if let Some(bool_expr) = self.expr().as_bool() {
            Some(TranslationEntry::new_scalar(
                bool_expr,
                self.depth(),
                self.coerced_values().clone(),
            ))
        } else {
            None
        }
    }

    pub fn as_bv(&self) -> Option<TranslationEntry<'ctx, BV<'ctx>>> {
        if let Some(bv_expr) = self.expr().as_bv() {
            Some(TranslationEntry::new_scalar(
                bv_expr,
                self.depth(),
                self.coerced_values().clone(),
            ))
        } else {
            None
        }
    }

    pub fn float_to_bv(&self) -> TranslationEntry<'ctx, BV<'ctx>> {
        if let Some(float_expr) = self.expr().as_float() {
            TranslationEntry::new_scalar(
                float_expr.to_ieee_bv(),
                self.depth() + 1,
                self.coerced_values().clone(),
            )
        } else {
            panic!("Cannot bitcast non-BV/Float expression to BV");
        }
    }

    pub fn as_float(&self) -> Option<TranslationEntry<'ctx, Float<'ctx>>> {
        if let Some(float_expr) = self.expr().as_float() {
            Some(TranslationEntry::new_scalar(
                float_expr,
                self.depth(),
                self.coerced_values().clone(),
            ))
        } else {
            None
        }
    }

    pub fn as_array(&self) -> Option<TranslationEntry<'ctx, Array<'ctx>>> {
        if let Some(array_expr) = self.expr().as_array() {
            Some(TranslationEntry::new_array(
                array_expr,
                self.depth(),
                self.coerced_values().clone(),
                self.array_info().cloned().unwrap(),
            ))
        } else {
            None
        }
    }

    pub fn bv_to_float(&self) -> TranslationEntry<'ctx, Float<'ctx>> {
        if let Some(bv_expr) = self.expr().as_bv() {
            TranslationEntry::new_scalar(
                bv_expr.bitcast_to_float(),
                self.depth() + 1,
                self.coerced_values().clone(),
            )
        } else {
            panic!("Cannot bitcast non-BV/Float expression to Float");
        }
    }

    pub fn kind(&self) -> AstKind {
        self.expr().kind()
    }

    pub fn simplify(self) -> TranslationEntry<'ctx, Dynamic<'ctx>> {
        let expr_before: Dynamic<'ctx> = self.expr().clone().into();
        let expr = expr_before.simplify();
        let new_identifiers = Solver::gather_const_apps(expr.clone());
        let new_coerced_values = self
            .coerced_values()
            .intersection(&new_identifiers)
            .into_iter()
            .map(|x| x.clone())
            .collect();
        if let Some(array_info) = self.array_info() {
            TranslationEntry::new_array(expr, self.depth(), new_coerced_values, array_info.clone())
        } else {
            TranslationEntry::new_scalar(expr, self.depth(), new_coerced_values)
        }
    }
}

fn assert_floating_point_sort<'ctx>(sort: Sort<'ctx>) -> Result<bool, Error> {
    match sort.float_exponent_size() {
        Some(ebits) => match sort.float_significand_size() {
            Some(sbits) => match (ebits, sbits) {
                (11, 53) => Ok(true),
                (8, 24) => Ok(false),
                _ => Err(Error::other(format!(
                    "sort {:?} has (sbits,ebits) = ({},{})",
                    sort, sbits, ebits
                ))),
            },
            None => Err(Error::other(format!("sort {:?} has no sbits field", sort))),
        },
        None => Err(Error::other(format!("sort {:?} has no ebits field", sort))),
    }
}

#[allow(unused)]
impl<'ctx> TranslationEntry<'ctx, Float<'ctx>> {
    pub fn to_other_float(&self, to_double: bool) -> TranslationEntry<'ctx, Float<'ctx>> {
        TranslationEntry::new_scalar(
            self.expr().to_other_float(to_double),
            self.depth() + 1,
            self.coerced_values().clone(),
        )
    }

    pub fn to_int(
        &self,
        bits: u32,
        signed: bool,
    ) -> Result<TranslationEntry<'ctx, BV<'ctx>>, Error> {
        let ctx = self.expr().get_ctx();
        let is_double = assert_floating_point_sort(self.expr().get_sort())?;
        let (ub, lb) = if is_double {
            (
                Float::from_f64(
                    ctx,
                    if signed {
                        i64::MAX as f64
                    } else {
                        u64::MAX as f64
                    },
                ),
                Float::from_f64(ctx, if signed { i64::MIN as f64 } else { 0.0 }),
            )
        } else {
            (
                Float::from_f32(
                    ctx,
                    if signed {
                        i32::MAX as f32
                    } else {
                        u32::MAX as f32
                    },
                ),
                Float::from_f32(ctx, if signed { i32::MIN as f32 } else { 0.0 }),
            )
        };
        let is_in_range = Bool::and(ctx, &[self.expr().le(&ub), self.expr().ge(&lb)]);
        let int_case = self.expr().to_int(bits, signed);
        let nan_case = BV::from_u64(ctx, 1 << (bits - 1), bits);
        let final_expr = is_in_range.ite(&int_case, &nan_case);

        Ok(TranslationEntry::new_scalar(
            final_expr,
            self.depth() + 1,
            self.coerced_values().clone(),
        ))
    }
}

#[allow(unused)]
impl<'ctx> TranslationEntry<'ctx, BV<'ctx>> {
    pub fn to_float(&self, is_double: bool, signed: bool) -> TranslationEntry<'ctx, Float<'ctx>> {
        TranslationEntry::new_scalar(
            self.expr().to_float(is_double, signed),
            self.depth() + 1,
            self.coerced_values().clone(),
        )
    }
}

macro_rules! impl_float_ternary_op {
    ($op:ident) => {
        pub fn $op(&self, other: &Self) -> TranslationEntry<'ctx, Float<'ctx>> {
            let rounding_mode = Float::round_towards_zero(&self.expr().get_ctx());
            let expr = rounding_mode.$op(self.expr(), other.expr());
            let coerced_values = self
                .coerced_values()
                .union(other.coerced_values())
                .into_iter()
                .map(|x| x.to_owned())
                .collect();
            TranslationEntry::new_scalar(
                expr,
                usize::max(self.depth(), other.depth()) + 1,
                coerced_values,
            )
        }
    };
}

macro_rules! impl_float_comparision_op {
    ($op:ident) => {
        pub fn $op(&self, other: &Self) -> TranslationEntry<'ctx, Bool<'ctx>> {
            let expr = self.expr().$op(other.expr());
            let coerced_values = self
                .coerced_values()
                .union(other.coerced_values())
                .into_iter()
                .map(|x| x.to_owned())
                .collect();
            TranslationEntry::new_scalar(
                expr,
                usize::max(self.depth(), other.depth()) + 1,
                coerced_values,
            )
        }
    };
}

macro_rules! impl_float_unary_op {
    ($op:ident) => {
        pub fn $op(&self) -> TranslationEntry<'ctx, Float<'ctx>> {
            let expr = self.expr().$op();
            let coerced_values = self.coerced_values().clone();
            TranslationEntry::new_scalar(expr, self.depth() + 1, coerced_values)
        }
    };
}

impl<'ctx> TranslationEntry<'ctx, Float<'ctx>> {
    pub fn to_ieee_bv(&self) -> TranslationEntry<'ctx, BV<'ctx>> {
        TranslationEntry::new_scalar(
            self.expr().to_ieee_bv(),
            self.depth() + 1,
            self.coerced_values().clone(),
        )
    }

    impl_float_unary_op!(unary_neg);
    impl_float_unary_op!(unary_abs);

    impl_float_comparision_op!(ge);
    impl_float_comparision_op!(gt);
    impl_float_comparision_op!(le);
    impl_float_comparision_op!(lt);
    impl_float_comparision_op!(_eq);

    impl_float_ternary_op!(add);
    impl_float_ternary_op!(mul);
    impl_float_ternary_op!(sub);
    impl_float_ternary_op!(div);

    pub fn rem(&self, other: &Self) -> TranslationEntry<'ctx, Float<'ctx>> {
        let expr = self.expr().rem(other.expr());
        let coerced_values = self
            .coerced_values()
            .union(other.coerced_values())
            .into_iter()
            .map(|x| x.to_owned())
            .collect();
        TranslationEntry::new_scalar(
            expr,
            usize::max(self.depth(), other.depth()) + 1,
            coerced_values,
        )
    }

    #[allow(dead_code)]
    pub fn is_nan(&self) -> TranslationEntry<'ctx, Bool<'ctx>> {
        let expr = self.expr().is_nan();
        TranslationEntry::new_scalar(expr, self.depth() + 1, self.coerced_values().clone())
    }

    pub fn unordered(&self, other: &Self) -> TranslationEntry<'ctx, Bool<'ctx>> {
        let is_nan = Bool::or(
            self.expr().get_ctx(),
            &[&self.expr().is_nan(), &other.expr().is_nan()],
        );
        let coerced_values = self
            .coerced_values()
            .union(other.coerced_values())
            .into_iter()
            .map(|x| x.to_owned())
            .collect();
        TranslationEntry::new_scalar(
            is_nan,
            usize::max(self.depth(), other.depth()) + 1,
            coerced_values,
        )
    }

    pub fn ordered(&self, other: &Self) -> TranslationEntry<'ctx, Bool<'ctx>> {
        let is_nan = Bool::and(
            self.expr().get_ctx(),
            &[&self.expr().is_nan().not(), &other.expr().is_nan().not()],
        );
        let coerced_values = self
            .coerced_values()
            .union(other.coerced_values())
            .into_iter()
            .map(|x| x.to_owned())
            .collect();
        TranslationEntry::new_scalar(
            is_nan,
            usize::max(self.depth(), other.depth()) + 1,
            coerced_values,
        )
    }
}

macro_rules! impl_bv_binop {
    ($op:ident) => {
        pub fn $op(&self, other: &Self) -> TranslationEntry<'ctx, BV<'ctx>> {
            let expr = self.expr().$op(other.expr());
            let coerced_values = self
                .coerced_values()
                .union(other.coerced_values())
                .into_iter()
                .map(|x| x.to_owned())
                .collect();
            TranslationEntry::new_scalar(
                expr,
                usize::max(self.depth(), other.depth()) + 1,
                coerced_values,
            )
        }
    };
}

macro_rules! impl_bv_comparison_op {
    ($op:ident) => {
        pub fn $op(&self, other: &Self) -> TranslationEntry<'ctx, Bool<'ctx>> {
            let expr = self.expr().$op(other.expr());
            let coerced_values = self
                .coerced_values()
                .union(other.coerced_values())
                .into_iter()
                .map(|x| x.to_owned())
                .collect();
            TranslationEntry::new_scalar(expr, self.depth() + 1, coerced_values)
        }
    };
}

macro_rules! impl_bv_unary_op {
    ($op:ident) => {
        pub fn $op(&self) -> TranslationEntry<'ctx, BV<'ctx>> {
            let expr = self.expr().$op();
            let coerced_values = self.coerced_values().clone();
            TranslationEntry::new_scalar(expr, self.depth() + 1, coerced_values)
        }
    };
}

impl<'ctx> TranslationEntry<'ctx, BV<'ctx>> {
    pub fn sign_ext(&self, bits: u32) -> Self {
        let expr = self.expr().sign_ext(bits);
        let coerced_values = self.coerced_values().clone();
        Self::new_scalar(expr, self.depth() + 1, coerced_values)
    }

    pub fn zero_ext(&self, bits: u32) -> Self {
        let expr = self.expr().zero_ext(bits);
        let coerced_values = self.coerced_values().clone();
        Self::new_scalar(expr, self.depth() + 1, coerced_values)
    }

    impl_bv_unary_op!(bvnot);
    impl_bv_unary_op!(bvneg);

    impl_bv_binop!(bvadd);
    impl_bv_binop!(bvsub);
    impl_bv_binop!(bvmul);
    impl_bv_binop!(bvudiv);
    impl_bv_binop!(bvsdiv);
    impl_bv_binop!(bvurem);
    impl_bv_binop!(bvsrem);
    impl_bv_binop!(bvshl);
    impl_bv_binop!(bvlshr);
    impl_bv_binop!(bvashr);
    impl_bv_binop!(bvand);
    impl_bv_binop!(bvor);
    impl_bv_binop!(bvxor);
    impl_bv_binop!(concat);

    impl_bv_comparison_op!(bvult);
    impl_bv_comparison_op!(bvule);
    impl_bv_comparison_op!(bvugt);
    impl_bv_comparison_op!(bvuge);
    impl_bv_comparison_op!(bvslt);
    impl_bv_comparison_op!(bvsle);
    impl_bv_comparison_op!(bvsgt);
    impl_bv_comparison_op!(bvsge);

    pub fn extract(&self, first_bit: u32, last_bit: u32) -> Self {
        let expr = self.expr().extract(first_bit, last_bit);
        let coerced_values = self.coerced_values().clone();
        Self::new_scalar(expr, self.depth() + 1, coerced_values)
    }

    pub fn get_size(&self) -> u32 {
        self.expr().get_size()
    }
}

impl<'ctx> TranslationEntry<'ctx, Bool<'ctx>> {
    pub fn not(&self) -> Self {
        let expr = self.expr().not();
        let coerced_values = self.coerced_values().clone();
        Self::new_scalar(expr, self.depth() + 1, coerced_values)
    }

    pub fn and(&self, other: &Self) -> Self {
        let expr = Bool::and(self.expr().get_ctx(), &[self.expr(), other.expr()]);
        let coerced_values = self
            .coerced_values()
            .union(other.coerced_values())
            .into_iter()
            .map(|x| x.to_owned())
            .collect();
        Self::new_scalar(
            expr,
            usize::max(self.depth(), other.depth()) + 1,
            coerced_values,
        )
    }

    pub fn or(&self, other: &Self) -> Self {
        let expr = Bool::or(self.expr().get_ctx(), &[self.expr(), other.expr()]);
        let coerced_values = self
            .coerced_values()
            .union(other.coerced_values())
            .into_iter()
            .map(|x| x.to_owned())
            .collect();
        Self::new_scalar(
            expr,
            usize::max(self.depth(), other.depth()) + 1,
            coerced_values,
        )
    }

    pub fn xor(&self, other: &Self) -> Self {
        let expr = self.expr().xor(other.expr());
        let coerced_values = self
            .coerced_values()
            .union(other.coerced_values())
            .into_iter()
            .map(|x| x.to_owned())
            .collect();
        Self::new_scalar(
            expr,
            usize::max(self.depth(), other.depth()) + 1,
            coerced_values,
        )
    }

    pub fn ite<'a>(
        &'a self,
        a: &TranslationEntry<'ctx, BV<'ctx>>,
        b: &TranslationEntry<'ctx, BV<'ctx>>,
    ) -> TranslationEntry<'ctx, BV<'ctx>> {
        let expr = self.expr().ite(a.expr(), b.expr());
        let coerced_values = self
            .coerced_values()
            .union(a.coerced_values())
            .into_iter()
            .map(|x| x.to_owned())
            .collect::<HashSet<_>>()
            .union(b.coerced_values())
            .into_iter()
            .map(|x| x.to_owned())
            .collect();
        TranslationEntry::new_scalar(
            expr,
            usize::max(self.depth(), a.depth().max(b.depth())) + 1,
            coerced_values,
        )
    }
}

pub trait VectorElement {}

impl VectorElement for BV<'_> {}
impl VectorElement for Float<'_> {}

impl<'ctx> TranslationEntry<'ctx, Array<'ctx>> {
    pub fn select(&self, index: u64) -> TranslationEntry<'ctx, Dynamic<'ctx>> {
        let index_expr = Int::from_u64(self.expr().get_ctx(), index);
        let expr = self.expr().select(&index_expr);
        let coerced_values = self.coerced_values().clone();
        TranslationEntry::new_scalar(expr, self.depth() + 1, coerced_values)
    }

    pub fn store<E: VectorElement + Ast<'ctx> + Clone + ToString + Into<Dynamic<'ctx>>>(
        &self,
        index: u64,
        value: &TranslationEntry<'ctx, E>,
    ) -> TranslationEntry<'ctx, Array<'ctx>> {
        let index_expr = Int::from_u64(self.expr().get_ctx(), index);
        let expr = self.expr().store(&index_expr, value.expr());
        let coerced_values = self
            .coerced_values()
            .union(value.coerced_values())
            .into_iter()
            .map(|x| x.to_owned())
            .collect();
        TranslationEntry::new_array(
            expr,
            self.depth() + 1,
            coerced_values,
            self.array_info().cloned().unwrap(),
        )
    }

    pub fn new_array_int(
        ctx: &'ctx z3::Context,
        name: &str,
        elem_cnt: u64,
        elem_size: u64,
    ) -> TranslationEntry<'ctx, Array<'ctx>> {
        let expr = Array::new_const(
            ctx,
            Symbol::String(name.to_string()),
            &Sort::int(ctx),
            &Sort::bitvector(ctx, elem_size as u32),
        );
        TranslationEntry::new_array(
            expr,
            0,
            HashSet::new(),
            ArrayInfo::Int {
                elem_size,
                elem_cnt,
            },
        )
    }

    pub fn new_array_fp(
        ctx: &'ctx z3::Context,
        name: &str,
        elem_cnt: u64,
        is_double: bool,
    ) -> TranslationEntry<'ctx, Array<'ctx>> {
        let sort = if is_double {
            Sort::double(ctx)
        } else {
            Sort::float32(ctx)
        };
        let expr = Array::new_const(
            ctx,
            Symbol::String(name.to_string()),
            &Sort::int(ctx),
            &sort,
        );
        TranslationEntry::new_array(
            expr,
            0,
            HashSet::new(),
            ArrayInfo::FP {
                is_double,
                elem_cnt,
            },
        )
    }
}

trait NotDynamic {}

impl NotDynamic for BV<'_> {}
impl NotDynamic for Bool<'_> {}
impl NotDynamic for Float<'_> {}

impl<'ctx, T> Into<TranslationEntry<'ctx, Dynamic<'ctx>>> for TranslationEntry<'ctx, T>
where
    T: Into<Dynamic<'ctx>> + Clone + ToString + NotDynamic,
{
    fn into(self) -> TranslationEntry<'ctx, Dynamic<'ctx>> {
        TranslationEntry::new_scalar(
            self.expr().clone().into(),
            self.depth(),
            self.coerced_values().clone(),
        )
    }
}

impl<'ctx> Into<TranslationEntry<'ctx, Dynamic<'ctx>>> for TranslationEntry<'ctx, Array<'ctx>> {
    fn into(self) -> TranslationEntry<'ctx, Dynamic<'ctx>> {
        TranslationEntry::new_array(
            self.expr().clone().into(),
            self.depth(),
            self.coerced_values().clone(),
            self.array_info().cloned().unwrap(),
        )
    }
}

impl<'ctx, T> From<T> for TranslationEntry<'ctx, T>
where
    T: Into<Dynamic<'ctx>> + Clone + ToString + NotDynamic,
{
    fn from(expr: T) -> Self {
        TranslationEntry::new_scalar(expr, 0, HashSet::new())
    }
}

impl<'ctx, T> From<T> for TranslationEntry<'ctx, Dynamic<'ctx>>
where
    T: Into<Dynamic<'ctx>> + ToString + Clone,
{
    fn from(expr: T) -> Self {
        TranslationEntry::new_scalar(expr.into(), 0, HashSet::new())
    }
}
