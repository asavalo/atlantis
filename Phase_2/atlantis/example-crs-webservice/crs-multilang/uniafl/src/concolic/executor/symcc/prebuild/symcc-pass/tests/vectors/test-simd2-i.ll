target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

define <8 x i64> @simple_function(<8 x i64> %0) {
  %2 = select <8 x i1> zeroinitializer, <8 x i64> zeroinitializer, <8 x i64> %0
  ret <8 x i64> %2
}
