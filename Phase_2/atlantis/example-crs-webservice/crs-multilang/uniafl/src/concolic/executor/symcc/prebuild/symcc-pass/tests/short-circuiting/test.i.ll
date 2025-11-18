; ModuleID = 'mock_vp.c'
source_filename = "mock_vp.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%struct.FuzzContext = type { ptr, i64 }
%struct.FuzzInput = type { i32, i32, i64 }
%struct.FuzzInputVec = type { [4 x i32], [4 x i32], i32 }

@.str = private unnamed_addr constant [7 x i8] c"malloc\00", align 1
@stderr = external global ptr, align 8
@.str.1 = private unnamed_addr constant [39 x i8] c"Data size exceeds context buffer size\0A\00", align 1
@.str.2 = private unnamed_addr constant [5 x i8] c"read\00", align 1
@.str.3 = private unnamed_addr constant [4 x i8] c"%d\0A\00", align 1
@.str.4 = private unnamed_addr constant [6 x i8] c"scanf\00", align 1
@.str.5 = private unnamed_addr constant [5 x i8] c"%zu\0A\00", align 1
@.str.6 = private unnamed_addr constant [19 x i8] c"data is too small\0A\00", align 1
@.str.7 = private unnamed_addr constant [22 x i8] c"%s: [%f, %f, %f, %f]\0A\00", align 1
@.str.8 = private unnamed_addr constant [22 x i8] c"%s: [%d, %d, %d, %d]\0A\00", align 1
@.str.9 = private unnamed_addr constant [18 x i8] c"data is too small\00", align 1
@.str.10 = private unnamed_addr constant [2 x i8] c"a\00", align 1
@.str.11 = private unnamed_addr constant [2 x i8] c"b\00", align 1
@.str.12 = private unnamed_addr constant [24 x i8] c"a < b condition not met\00", align 1
@.str.13 = private unnamed_addr constant [5 x i8] c"eq_c\00", align 1
@.str.14 = private unnamed_addr constant [6 x i8] c"c * c\00", align 1
@.str.15 = private unnamed_addr constant [39 x i8] c"Values do not match expected condition\00", align 1
@stdin = external global ptr, align 8
@.str.16 = private unnamed_addr constant [61 x i8] c"Failed to read data (%lu bytes required vs. %ld bytes read)\0A\00", align 1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @fuzz_context_create(i64 noundef %0) #0 {
  %2 = alloca ptr, align 8
  %3 = alloca i64, align 8
  %4 = alloca ptr, align 8
  store i64 %0, ptr %3, align 8
  %5 = call noalias ptr @malloc(i64 noundef 16) #8
  store ptr %5, ptr %4, align 8
  %6 = load ptr, ptr %4, align 8
  %7 = icmp ne ptr %6, null
  br i1 %7, label %9, label %8

8:                                                ; preds = %1
  call void @perror(ptr noundef @.str) #9
  store ptr null, ptr %2, align 8
  br label %25

9:                                                ; preds = %1
  %10 = load i64, ptr %3, align 8
  %11 = call noalias ptr @malloc(i64 noundef %10) #8
  %12 = load ptr, ptr %4, align 8
  %13 = getelementptr inbounds %struct.FuzzContext, ptr %12, i32 0, i32 0
  store ptr %11, ptr %13, align 8
  %14 = load ptr, ptr %4, align 8
  %15 = getelementptr inbounds %struct.FuzzContext, ptr %14, i32 0, i32 0
  %16 = load ptr, ptr %15, align 8
  %17 = icmp ne ptr %16, null
  br i1 %17, label %20, label %18

18:                                               ; preds = %9
  call void @perror(ptr noundef @.str) #9
  %19 = load ptr, ptr %4, align 8
  call void @free(ptr noundef %19) #10
  store ptr null, ptr %2, align 8
  br label %25

20:                                               ; preds = %9
  %21 = load i64, ptr %3, align 8
  %22 = load ptr, ptr %4, align 8
  %23 = getelementptr inbounds %struct.FuzzContext, ptr %22, i32 0, i32 1
  store i64 %21, ptr %23, align 8
  %24 = load ptr, ptr %4, align 8
  store ptr %24, ptr %2, align 8
  br label %25

25:                                               ; preds = %20, %18, %8
  %26 = load ptr, ptr %2, align 8
  ret ptr %26
}

; Function Attrs: nounwind allocsize(0)
declare noalias ptr @malloc(i64 noundef) #1

; Function Attrs: cold
declare void @perror(ptr noundef) #2

; Function Attrs: nounwind
declare void @free(ptr noundef) #3

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @fuzz_context_destroy(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  %3 = load ptr, ptr %2, align 8
  %4 = icmp ne ptr %3, null
  br i1 %4, label %5, label %10

5:                                                ; preds = %1
  %6 = load ptr, ptr %2, align 8
  %7 = getelementptr inbounds %struct.FuzzContext, ptr %6, i32 0, i32 0
  %8 = load ptr, ptr %7, align 8
  call void @free(ptr noundef %8) #10
  %9 = load ptr, ptr %2, align 8
  call void @free(ptr noundef %9) #10
  br label %10

10:                                               ; preds = %5, %1
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @fuzz_context_write(ptr noundef %0, i64 noundef %1, i8 noundef signext %2) #0 {
  %4 = alloca ptr, align 8
  %5 = alloca i64, align 8
  %6 = alloca i8, align 1
  store ptr %0, ptr %4, align 8
  store i64 %1, ptr %5, align 8
  store i8 %2, ptr %6, align 1
  %7 = load i64, ptr %5, align 8
  %8 = load ptr, ptr %4, align 8
  %9 = getelementptr inbounds %struct.FuzzContext, ptr %8, i32 0, i32 1
  %10 = load i64, ptr %9, align 8
  %11 = icmp ugt i64 %7, %10
  br i1 %11, label %12, label %15

12:                                               ; preds = %3
  %13 = load ptr, ptr @stderr, align 8
  %14 = call i32 (ptr, ptr, ...) @fprintf(ptr noundef %13, ptr noundef @.str.1)
  br label %22

15:                                               ; preds = %3
  %16 = load i8, ptr %6, align 1
  %17 = load ptr, ptr %4, align 8
  %18 = getelementptr inbounds %struct.FuzzContext, ptr %17, i32 0, i32 0
  %19 = load ptr, ptr %18, align 8
  %20 = load i64, ptr %5, align 8
  %21 = getelementptr inbounds i8, ptr %19, i64 %20
  store i8 %16, ptr %21, align 1
  br label %22

22:                                               ; preds = %15, %12
  ret void
}

declare i32 @fprintf(ptr noundef, ptr noundef, ...) #4

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @func_a(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  %3 = alloca %struct.FuzzInput, align 8
  store ptr %0, ptr %2, align 8
  %4 = call i64 @read(i32 noundef 0, ptr noundef %3, i64 noundef 16)
  %5 = icmp ult i64 %4, 16
  br i1 %5, label %6, label %7

6:                                                ; preds = %1
  call void @perror(ptr noundef @.str.2) #9
  br label %25

7:                                                ; preds = %1
  %8 = getelementptr inbounds %struct.FuzzInput, ptr %3, i32 0, i32 0
  %9 = load i32, ptr %8, align 8
  %10 = getelementptr inbounds %struct.FuzzInput, ptr %3, i32 0, i32 1
  %11 = load i32, ptr %10, align 4
  %12 = mul nsw i32 %9, %11
  %13 = icmp eq i32 %12, 24201480
  br i1 %13, label %14, label %25

14:                                               ; preds = %7
  %15 = getelementptr inbounds %struct.FuzzInput, ptr %3, i32 0, i32 0
  %16 = load i32, ptr %15, align 8
  %17 = getelementptr inbounds %struct.FuzzInput, ptr %3, i32 0, i32 1
  %18 = load i32, ptr %17, align 4
  %19 = add nsw i32 %16, %18
  %20 = icmp eq i32 %19, 9839
  br i1 %20, label %21, label %25

21:                                               ; preds = %14
  %22 = load ptr, ptr %2, align 8
  %23 = getelementptr inbounds %struct.FuzzInput, ptr %3, i32 0, i32 2
  %24 = load i64, ptr %23, align 8
  call void @fuzz_context_write(ptr noundef %22, i64 noundef %24, i8 noundef signext -1)
  br label %25

25:                                               ; preds = %6, %21, %14, %7
  ret void
}

declare i64 @read(i32 noundef, ptr noundef, i64 noundef) #4

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @func_b(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  %3 = alloca i32, align 4
  %4 = alloca i32, align 4
  %5 = alloca i64, align 8
  store ptr %0, ptr %2, align 8
  %6 = call i32 (ptr, ...) @__isoc99_scanf(ptr noundef @.str.3, ptr noundef %3)
  %7 = icmp ne i32 %6, 1
  br i1 %7, label %8, label %9

8:                                                ; preds = %1
  call void @perror(ptr noundef @.str.4) #9
  br label %30

9:                                                ; preds = %1
  %10 = call i32 (ptr, ...) @__isoc99_scanf(ptr noundef @.str.3, ptr noundef %4)
  %11 = icmp ne i32 %10, 1
  br i1 %11, label %12, label %13

12:                                               ; preds = %9
  call void @perror(ptr noundef @.str.4) #9
  br label %30

13:                                               ; preds = %9
  %14 = call i32 (ptr, ...) @__isoc99_scanf(ptr noundef @.str.5, ptr noundef %5)
  %15 = icmp ne i32 %14, 1
  br i1 %15, label %16, label %17

16:                                               ; preds = %13
  call void @perror(ptr noundef @.str.4) #9
  br label %30

17:                                               ; preds = %13
  %18 = load i32, ptr %3, align 4
  %19 = load i32, ptr %4, align 4
  %20 = mul nsw i32 %18, %19
  %21 = icmp eq i32 %20, 24201480
  br i1 %21, label %22, label %30

22:                                               ; preds = %17
  %23 = load i32, ptr %3, align 4
  %24 = load i32, ptr %4, align 4
  %25 = add nsw i32 %23, %24
  %26 = icmp eq i32 %25, 9839
  br i1 %26, label %27, label %30

27:                                               ; preds = %22
  %28 = load ptr, ptr %2, align 8
  %29 = load i64, ptr %5, align 8
  call void @fuzz_context_write(ptr noundef %28, i64 noundef %29, i8 noundef signext -1)
  br label %30

30:                                               ; preds = %8, %12, %16, %27, %22, %17
  ret void
}

declare i32 @__isoc99_scanf(ptr noundef, ...) #4

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @func_c(ptr noundef %0, i64 noundef %1, ptr noundef %2) #0 {
  %4 = alloca ptr, align 8
  %5 = alloca i64, align 8
  %6 = alloca ptr, align 8
  %7 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store i64 %1, ptr %5, align 8
  store ptr %2, ptr %6, align 8
  %8 = load i64, ptr %5, align 8
  %9 = icmp ult i64 %8, 16
  br i1 %9, label %10, label %12

10:                                               ; preds = %3
  %11 = call i32 @puts(ptr noundef @.str.6)
  br label %36

12:                                               ; preds = %3
  %13 = load ptr, ptr %4, align 8
  store ptr %13, ptr %7, align 8
  %14 = load ptr, ptr %7, align 8
  %15 = getelementptr inbounds %struct.FuzzInput, ptr %14, i32 0, i32 0
  %16 = load i32, ptr %15, align 8
  %17 = load ptr, ptr %7, align 8
  %18 = getelementptr inbounds %struct.FuzzInput, ptr %17, i32 0, i32 1
  %19 = load i32, ptr %18, align 4
  %20 = mul nsw i32 %16, %19
  %21 = icmp eq i32 %20, 24201480
  br i1 %21, label %22, label %36

22:                                               ; preds = %12
  %23 = load ptr, ptr %7, align 8
  %24 = getelementptr inbounds %struct.FuzzInput, ptr %23, i32 0, i32 0
  %25 = load i32, ptr %24, align 8
  %26 = load ptr, ptr %7, align 8
  %27 = getelementptr inbounds %struct.FuzzInput, ptr %26, i32 0, i32 1
  %28 = load i32, ptr %27, align 4
  %29 = add nsw i32 %25, %28
  %30 = icmp eq i32 %29, 9839
  br i1 %30, label %31, label %36

31:                                               ; preds = %22
  %32 = load ptr, ptr %6, align 8
  %33 = load ptr, ptr %7, align 8
  %34 = getelementptr inbounds %struct.FuzzInput, ptr %33, i32 0, i32 2
  %35 = load i64, ptr %34, align 8
  call void @fuzz_context_write(ptr noundef %32, i64 noundef %35, i8 noundef signext -1)
  br label %36

36:                                               ; preds = %10, %31, %22, %12
  ret void
}

declare i32 @puts(ptr noundef) #4

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @print_float_vector(<4 x float> noundef %0, ptr noundef %1) #5 {
  %3 = alloca ptr, align 8
  %4 = alloca <4 x float>, align 16
  %5 = alloca <4 x float>, align 16
  %6 = alloca ptr, align 8
  %7 = alloca [4 x float], align 16
  store <4 x float> %0, ptr %5, align 16
  store ptr %1, ptr %6, align 8
  %8 = getelementptr inbounds [4 x float], ptr %7, i64 0, i64 0
  %9 = load <4 x float>, ptr %5, align 16
  store ptr %8, ptr %3, align 8
  store <4 x float> %9, ptr %4, align 16
  %10 = load <4 x float>, ptr %4, align 16
  %11 = load ptr, ptr %3, align 8
  store <4 x float> %10, ptr %11, align 1
  %12 = load ptr, ptr %6, align 8
  %13 = getelementptr inbounds [4 x float], ptr %7, i64 0, i64 0
  %14 = load float, ptr %13, align 16
  %15 = fpext float %14 to double
  %16 = getelementptr inbounds [4 x float], ptr %7, i64 0, i64 1
  %17 = load float, ptr %16, align 4
  %18 = fpext float %17 to double
  %19 = getelementptr inbounds [4 x float], ptr %7, i64 0, i64 2
  %20 = load float, ptr %19, align 8
  %21 = fpext float %20 to double
  %22 = getelementptr inbounds [4 x float], ptr %7, i64 0, i64 3
  %23 = load float, ptr %22, align 4
  %24 = fpext float %23 to double
  %25 = call i32 (ptr, ...) @printf(ptr noundef @.str.7, ptr noundef %12, double noundef %15, double noundef %18, double noundef %21, double noundef %24)
  ret void
}

declare i32 @printf(ptr noundef, ...) #4

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @print_int_vector(<2 x i64> noundef %0, ptr noundef %1) #5 {
  %3 = alloca ptr, align 8
  %4 = alloca <2 x i64>, align 16
  %5 = alloca <2 x i64>, align 16
  %6 = alloca ptr, align 8
  %7 = alloca [4 x i32], align 16
  store <2 x i64> %0, ptr %5, align 16
  store ptr %1, ptr %6, align 8
  %8 = getelementptr inbounds [4 x i32], ptr %7, i64 0, i64 0
  %9 = load <2 x i64>, ptr %5, align 16
  store ptr %8, ptr %3, align 8
  store <2 x i64> %9, ptr %4, align 16
  %10 = load <2 x i64>, ptr %4, align 16
  %11 = load ptr, ptr %3, align 8
  store <2 x i64> %10, ptr %11, align 1
  %12 = load ptr, ptr %6, align 8
  %13 = getelementptr inbounds [4 x i32], ptr %7, i64 0, i64 0
  %14 = load i32, ptr %13, align 16
  %15 = getelementptr inbounds [4 x i32], ptr %7, i64 0, i64 1
  %16 = load i32, ptr %15, align 4
  %17 = getelementptr inbounds [4 x i32], ptr %7, i64 0, i64 2
  %18 = load i32, ptr %17, align 8
  %19 = getelementptr inbounds [4 x i32], ptr %7, i64 0, i64 3
  %20 = load i32, ptr %19, align 4
  %21 = call i32 (ptr, ...) @printf(ptr noundef @.str.8, ptr noundef %12, i32 noundef %14, i32 noundef %16, i32 noundef %18, i32 noundef %20)
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local <2 x i64> @square_m128i(<2 x i64> noundef %0) #5 {
  %2 = alloca <2 x i64>, align 16
  %3 = alloca <2 x i64>, align 16
  %4 = alloca <2 x i64>, align 16
  %5 = alloca <2 x i64>, align 16
  %6 = alloca <2 x i64>, align 16
  %7 = alloca <2 x i64>, align 16
  %8 = alloca <2 x i64>, align 16
  %9 = alloca <2 x i64>, align 16
  %10 = alloca <2 x i64>, align 16
  %11 = alloca <2 x i64>, align 16
  %12 = alloca <2 x i64>, align 16
  %13 = alloca <2 x i64>, align 16
  store <2 x i64> %0, ptr %8, align 16
  %14 = load <2 x i64>, ptr %8, align 16
  %15 = bitcast <2 x i64> %14 to <4 x i32>
  %16 = shufflevector <4 x i32> %15, <4 x i32> poison, <4 x i32> <i32 0, i32 0, i32 2, i32 2>
  %17 = bitcast <4 x i32> %16 to <2 x i64>
  store <2 x i64> %17, ptr %9, align 16
  %18 = load <2 x i64>, ptr %9, align 16
  %19 = load <2 x i64>, ptr %9, align 16
  store <2 x i64> %18, ptr %4, align 16
  store <2 x i64> %19, ptr %5, align 16
  %20 = load <2 x i64>, ptr %4, align 16
  %21 = bitcast <2 x i64> %20 to <4 x i32>
  %22 = load <2 x i64>, ptr %5, align 16
  %23 = bitcast <2 x i64> %22 to <4 x i32>
  %24 = and <2 x i64> %20, <i64 4294967295, i64 4294967295>
  %25 = and <2 x i64> %22, <i64 4294967295, i64 4294967295>
  %26 = mul <2 x i64> %24, %25
  store <2 x i64> %26, ptr %10, align 16
  %27 = load <2 x i64>, ptr %8, align 16
  %28 = bitcast <2 x i64> %27 to <4 x i32>
  %29 = shufflevector <4 x i32> %28, <4 x i32> poison, <4 x i32> <i32 1, i32 1, i32 3, i32 3>
  %30 = bitcast <4 x i32> %29 to <2 x i64>
  store <2 x i64> %30, ptr %11, align 16
  %31 = load <2 x i64>, ptr %11, align 16
  %32 = load <2 x i64>, ptr %11, align 16
  store <2 x i64> %31, ptr %6, align 16
  store <2 x i64> %32, ptr %7, align 16
  %33 = load <2 x i64>, ptr %6, align 16
  %34 = bitcast <2 x i64> %33 to <4 x i32>
  %35 = load <2 x i64>, ptr %7, align 16
  %36 = bitcast <2 x i64> %35 to <4 x i32>
  %37 = and <2 x i64> %33, <i64 4294967295, i64 4294967295>
  %38 = and <2 x i64> %35, <i64 4294967295, i64 4294967295>
  %39 = mul <2 x i64> %37, %38
  store <2 x i64> %39, ptr %12, align 16
  %40 = load <2 x i64>, ptr %10, align 16
  %41 = bitcast <2 x i64> %40 to <4 x i32>
  %42 = shufflevector <4 x i32> %41, <4 x i32> poison, <4 x i32> <i32 0, i32 2, i32 0, i32 0>
  %43 = bitcast <4 x i32> %42 to <2 x i64>
  %44 = load <2 x i64>, ptr %12, align 16
  %45 = bitcast <2 x i64> %44 to <4 x i32>
  %46 = shufflevector <4 x i32> %45, <4 x i32> poison, <4 x i32> <i32 0, i32 2, i32 0, i32 0>
  %47 = bitcast <4 x i32> %46 to <2 x i64>
  store <2 x i64> %43, ptr %2, align 16
  store <2 x i64> %47, ptr %3, align 16
  %48 = load <2 x i64>, ptr %2, align 16
  %49 = bitcast <2 x i64> %48 to <4 x i32>
  %50 = load <2 x i64>, ptr %3, align 16
  %51 = bitcast <2 x i64> %50 to <4 x i32>
  %52 = shufflevector <4 x i32> %49, <4 x i32> %51, <4 x i32> <i32 0, i32 4, i32 1, i32 5>
  %53 = bitcast <4 x i32> %52 to <2 x i64>
  store <2 x i64> %53, ptr %13, align 16
  %54 = load <2 x i64>, ptr %13, align 16
  ret <2 x i64> %54
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @func_d(ptr noundef %0, i64 noundef %1, ptr noundef %2) #5 {
  %4 = alloca <2 x i64>, align 16
  %5 = alloca <2 x i64>, align 16
  %6 = alloca <2 x i64>, align 16
  %7 = alloca i32, align 4
  %8 = alloca i32, align 4
  %9 = alloca i32, align 4
  %10 = alloca i32, align 4
  %11 = alloca <4 x i32>, align 16
  %12 = alloca <4 x float>, align 16
  %13 = alloca <4 x float>, align 16
  %14 = alloca <4 x float>, align 16
  %15 = alloca <4 x float>, align 16
  %16 = alloca <4 x float>, align 16
  %17 = alloca <4 x float>, align 16
  %18 = alloca <4 x float>, align 16
  %19 = alloca <4 x float>, align 16
  %20 = alloca <4 x float>, align 16
  %21 = alloca <4 x float>, align 16
  %22 = alloca <4 x float>, align 16
  %23 = alloca ptr, align 8
  %24 = alloca ptr, align 8
  %25 = alloca ptr, align 8
  %26 = alloca <2 x i64>, align 16
  %27 = alloca ptr, align 8
  %28 = alloca i64, align 8
  %29 = alloca ptr, align 8
  %30 = alloca ptr, align 8
  %31 = alloca [4 x float], align 16
  %32 = alloca [4 x i32], align 16
  %33 = alloca i32, align 4
  %34 = alloca <4 x float>, align 16
  %35 = alloca <4 x float>, align 16
  %36 = alloca <2 x i64>, align 16
  %37 = alloca <2 x i64>, align 16
  store ptr %0, ptr %27, align 8
  store i64 %1, ptr %28, align 8
  store ptr %2, ptr %29, align 8
  %38 = load i64, ptr %28, align 8
  %39 = icmp ult i64 %38, 36
  br i1 %39, label %40, label %42

40:                                               ; preds = %3
  %41 = call i32 @puts(ptr noundef @.str.9)
  br label %141

42:                                               ; preds = %3
  %43 = load ptr, ptr %27, align 8
  store ptr %43, ptr %30, align 8
  store i32 0, ptr %33, align 4
  br label %44

44:                                               ; preds = %58, %42
  %45 = load i32, ptr %33, align 4
  %46 = icmp slt i32 %45, 4
  br i1 %46, label %47, label %61

47:                                               ; preds = %44
  %48 = load ptr, ptr %30, align 8
  %49 = getelementptr inbounds %struct.FuzzInputVec, ptr %48, i32 0, i32 0
  %50 = load i32, ptr %33, align 4
  %51 = sext i32 %50 to i64
  %52 = getelementptr inbounds [4 x i32], ptr %49, i64 0, i64 %51
  %53 = load i32, ptr %52, align 1
  %54 = sitofp i32 %53 to float
  %55 = load i32, ptr %33, align 4
  %56 = sext i32 %55 to i64
  %57 = getelementptr inbounds [4 x float], ptr %31, i64 0, i64 %56
  store float %54, ptr %57, align 4
  br label %58

58:                                               ; preds = %47
  %59 = load i32, ptr %33, align 4
  %60 = add nsw i32 %59, 1
  store i32 %60, ptr %33, align 4
  br label %44, !llvm.loop !6

61:                                               ; preds = %44
  %62 = getelementptr inbounds [4 x float], ptr %31, i64 0, i64 0
  store ptr %62, ptr %23, align 8
  %63 = load ptr, ptr %23, align 8
  %64 = load <4 x float>, ptr %63, align 1
  store <4 x float> %64, ptr %34, align 16
  %65 = load ptr, ptr %30, align 8
  %66 = getelementptr inbounds %struct.FuzzInputVec, ptr %65, i32 0, i32 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 16 %31, ptr align 1 %66, i64 16, i1 false)
  %67 = getelementptr inbounds [4 x float], ptr %31, i64 0, i64 0
  store ptr %67, ptr %24, align 8
  %68 = load ptr, ptr %24, align 8
  %69 = load <4 x float>, ptr %68, align 1
  store <4 x float> %69, ptr %35, align 16
  %70 = load <4 x float>, ptr %34, align 16
  call void @print_float_vector(<4 x float> noundef %70, ptr noundef @.str.10)
  %71 = load <4 x float>, ptr %35, align 16
  call void @print_float_vector(<4 x float> noundef %71, ptr noundef @.str.11)
  %72 = load <4 x float>, ptr %34, align 16
  %73 = load <4 x float>, ptr %35, align 16
  store <4 x float> %72, ptr %19, align 16
  store <4 x float> %73, ptr %20, align 16
  %74 = load <4 x float>, ptr %19, align 16
  %75 = load <4 x float>, ptr %20, align 16
  %76 = fcmp olt <4 x float> %74, %75
  %77 = sext <4 x i1> %76 to <4 x i32>
  %78 = bitcast <4 x i32> %77 to <4 x float>
  store <4 x float> %78, ptr %21, align 16
  %79 = load <4 x float>, ptr %21, align 16
  %80 = call i32 @llvm.x86.sse.movmsk.ps(<4 x float> %79)
  %81 = icmp ne i32 %80, 15
  br i1 %81, label %82, label %84

82:                                               ; preds = %61
  %83 = call i32 @puts(ptr noundef @.str.12)
  br label %141

84:                                               ; preds = %61
  %85 = load <4 x float>, ptr %34, align 16
  %86 = load <4 x float>, ptr %34, align 16
  store <4 x float> %85, ptr %12, align 16
  store <4 x float> %86, ptr %13, align 16
  %87 = load <4 x float>, ptr %12, align 16
  %88 = load <4 x float>, ptr %13, align 16
  %89 = fmul <4 x float> %87, %88
  %90 = load <4 x float>, ptr %35, align 16
  %91 = load <4 x float>, ptr %35, align 16
  store <4 x float> %90, ptr %14, align 16
  store <4 x float> %91, ptr %15, align 16
  %92 = load <4 x float>, ptr %14, align 16
  %93 = load <4 x float>, ptr %15, align 16
  %94 = fmul <4 x float> %92, %93
  store <4 x float> %89, ptr %16, align 16
  store <4 x float> %94, ptr %17, align 16
  %95 = load <4 x float>, ptr %16, align 16
  %96 = load <4 x float>, ptr %17, align 16
  %97 = fadd <4 x float> %95, %96
  store <4 x float> %97, ptr %18, align 16
  %98 = load <4 x float>, ptr %18, align 16
  %99 = call <4 x i32> @llvm.x86.sse2.cvttps2dq(<4 x float> %98)
  %100 = bitcast <4 x i32> %99 to <2 x i64>
  store <2 x i64> %100, ptr %36, align 16
  %101 = load <2 x i64>, ptr %36, align 16
  call void @print_int_vector(<2 x i64> noundef %101, ptr noundef @.str.13)
  %102 = getelementptr inbounds [4 x i32], ptr %32, i64 0, i64 0
  %103 = load <2 x i64>, ptr %36, align 16
  store ptr %102, ptr %25, align 8
  store <2 x i64> %103, ptr %26, align 16
  %104 = load <2 x i64>, ptr %26, align 16
  %105 = load ptr, ptr %25, align 8
  store <2 x i64> %104, ptr %105, align 1
  store i32 221, ptr %7, align 4
  store i32 221, ptr %8, align 4
  store i32 205, ptr %9, align 4
  store i32 205, ptr %10, align 4
  %106 = load i32, ptr %10, align 4
  %107 = insertelement <4 x i32> poison, i32 %106, i32 0
  %108 = load i32, ptr %9, align 4
  %109 = insertelement <4 x i32> %107, i32 %108, i32 1
  %110 = load i32, ptr %8, align 4
  %111 = insertelement <4 x i32> %109, i32 %110, i32 2
  %112 = load i32, ptr %7, align 4
  %113 = insertelement <4 x i32> %111, i32 %112, i32 3
  store <4 x i32> %113, ptr %11, align 16
  %114 = load <4 x i32>, ptr %11, align 16
  %115 = bitcast <4 x i32> %114 to <2 x i64>
  store <2 x i64> %115, ptr %37, align 16
  %116 = load <2 x i64>, ptr %37, align 16
  %117 = call <2 x i64> @square_m128i(<2 x i64> noundef %116)
  call void @print_int_vector(<2 x i64> noundef %117, ptr noundef @.str.14)
  %118 = load <2 x i64>, ptr %37, align 16
  %119 = call <2 x i64> @square_m128i(<2 x i64> noundef %118)
  %120 = load <2 x i64>, ptr %36, align 16
  store <2 x i64> %119, ptr %4, align 16
  store <2 x i64> %120, ptr %5, align 16
  %121 = load <2 x i64>, ptr %4, align 16
  %122 = bitcast <2 x i64> %121 to <4 x i32>
  %123 = load <2 x i64>, ptr %5, align 16
  %124 = bitcast <2 x i64> %123 to <4 x i32>
  %125 = icmp eq <4 x i32> %122, %124
  %126 = sext <4 x i1> %125 to <4 x i32>
  %127 = bitcast <4 x i32> %126 to <2 x i64>
  store <2 x i64> %127, ptr %6, align 16
  %128 = load <2 x i64>, ptr %6, align 16
  %129 = bitcast <2 x i64> %128 to <4 x float>
  store <4 x float> %129, ptr %22, align 16
  %130 = load <4 x float>, ptr %22, align 16
  %131 = call i32 @llvm.x86.sse.movmsk.ps(<4 x float> %130)
  %132 = icmp eq i32 %131, 15
  br i1 %132, label %133, label %139

133:                                              ; preds = %84
  %134 = load ptr, ptr %29, align 8
  %135 = load ptr, ptr %30, align 8
  %136 = getelementptr inbounds %struct.FuzzInputVec, ptr %135, i32 0, i32 2
  %137 = load i32, ptr %136, align 1
  %138 = sext i32 %137 to i64
  call void @fuzz_context_write(ptr noundef %134, i64 noundef %138, i8 noundef signext -1)
  br label %141

139:                                              ; preds = %84
  %140 = call i32 @puts(ptr noundef @.str.15)
  br label %141

141:                                              ; preds = %40, %82, %139, %133
  ret void
}

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly, ptr noalias nocapture readonly, i64, i1 immarg) #6

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main() #0 {
  %1 = alloca i32, align 4
  %2 = alloca [36 x i8], align 16
  %3 = alloca i64, align 8
  %4 = alloca ptr, align 8
  store i32 0, ptr %1, align 4
  %5 = getelementptr inbounds [36 x i8], ptr %2, i64 0, i64 0
  %6 = load ptr, ptr @stdin, align 8
  %7 = call i64 @fread(ptr noundef %5, i64 noundef 1, i64 noundef 36, ptr noundef %6)
  store i64 %7, ptr %3, align 8
  %8 = icmp ne i64 %7, 36
  br i1 %8, label %9, label %13

9:                                                ; preds = %0
  %10 = load ptr, ptr @stderr, align 8
  %11 = load i64, ptr %3, align 8
  %12 = call i32 (ptr, ptr, ...) @fprintf(ptr noundef %10, ptr noundef @.str.16, i64 noundef 36, i64 noundef %11)
  store i32 -1, ptr %1, align 4
  br label %17

13:                                               ; preds = %0
  %14 = call ptr @fuzz_context_create(i64 noundef 300)
  store ptr %14, ptr %4, align 8
  %15 = getelementptr inbounds [36 x i8], ptr %2, i64 0, i64 0
  %16 = load ptr, ptr %4, align 8
  call void @func_d(ptr noundef %15, i64 noundef 36, ptr noundef %16)
  store i32 0, ptr %1, align 4
  br label %17

17:                                               ; preds = %13, %9
  %18 = load i32, ptr %1, align 4
  ret i32 %18
}

declare i64 @fread(ptr noundef, i64 noundef, i64 noundef, ptr noundef) #4

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(none)
declare i32 @llvm.x86.sse.movmsk.ps(<4 x float>) #7

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(none)
declare <4 x i32> @llvm.x86.sse2.cvttps2dq(<4 x float>) #7

attributes #0 = { noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nounwind allocsize(0) "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #2 = { cold "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #3 = { nounwind "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #4 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #5 = { noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="128" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #6 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }
attributes #7 = { nocallback nofree nosync nounwind willreturn memory(none) }
attributes #8 = { nounwind allocsize(0) }
attributes #9 = { cold }
attributes #10 = { nounwind }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{i32 7, !"frame-pointer", i32 2}
!5 = !{!"Ubuntu clang version 18.1.8 (++20240731025043+3b5b5c1ec4a3-1~exp1~20240731145144.92)"}
!6 = distinct !{!6, !7}
!7 = !{!"llvm.loop.mustprogress"}
