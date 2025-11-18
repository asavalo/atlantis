; ModuleID = 'test-harness.c'
source_filename = "test-harness.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@llvm.global_ctors = appending global [1 x { i32, ptr, ptr }] [{ i32, ptr, ptr } { i32 -1, ptr @__sym_ctor, ptr null }]
@llvm.used = appending global [1 x ptr] [ptr @__sym_ctor], section "llvm.metadata"
@"_sym_pcid_to_loc./home/procfs/CRS-multilang/uniafl/src/concolic/executor/symcc/test-harness/test-harness.c" = constant [8 x i64] [i64 2143228267094992651, i64 -4684694841351493131, i64 6, i64 7, i64 -6339501747245376080, i64 -4684694841351493131, i64 9, i64 19], section ".symcc_maps"
@"_sym_srchash_to_path./home/procfs/CRS-multilang/uniafl/src/concolic/executor/symcc/test-harness/test-harness.c" = constant [14 x i64] [i64 -4684694841351493131, i64 12, i64 8246143030389598255, i64 6003935124316906351, i64 7020101867920518445, i64 7377293587742943086, i64 8026311065072775020, i64 7291155626178077550, i64 3418917613103965560, i64 7310520199045544307, i64 7308905007954097267, i64 3275369708583351155, i64 3347145827548291432, i64 99], section ".symcc_maps"

; Function Attrs: nounwind uwtable
define dso_local i32 @LLVMFuzzerTestOneInput(ptr noundef %0, i64 noundef %1) local_unnamed_addr #0 !dbg !23 {
  tail call void @_sym_notify_basic_block(i64 93827663690992) #4, !dbg !40
  %3 = tail call ptr @_sym_get_parameter_expression(i8 0) #4, !dbg !40
  %4 = tail call ptr @_sym_get_parameter_expression(i8 1) #4, !dbg !40
  tail call void @llvm.dbg.value(metadata ptr %0, metadata !37, metadata !DIExpression()), !dbg !42
  tail call void @llvm.dbg.value(metadata i64 %1, metadata !38, metadata !DIExpression()), !dbg !42
  %5 = icmp eq ptr %4, null, !dbg !40
  br i1 %5, label %9, label %6, !dbg !40

6:                                                ; preds = %2
  %7 = tail call ptr @_sym_build_integer(i64 20, i8 64) #4, !dbg !40
  %8 = tail call ptr @_sym_build_unsigned_less_than(ptr nonnull %4, ptr %7) #4, !dbg !40
  br label %9, !dbg !40

9:                                                ; preds = %2, %6
  %10 = phi ptr [ null, %2 ], [ %8, %6 ], !dbg !40
  %11 = icmp ult i64 %1, 20, !dbg !40
  %12 = icmp eq ptr %10, null, !dbg !43
  br i1 %12, label %14, label %13, !dbg !43

13:                                               ; preds = %9
  tail call void @_sym_push_path_constraint(ptr nonnull %10, i1 %11, i64 2143228267094992651) #4, !dbg !43
  br label %14, !dbg !43

14:                                               ; preds = %9, %13
  br i1 %11, label %45, label %15, !dbg !43

15:                                               ; preds = %14
  tail call void @_sym_notify_basic_block(i64 93827664025840) #4, !dbg !44
  tail call void @llvm.dbg.value(metadata ptr %0, metadata !39, metadata !DIExpression()), !dbg !42
  tail call void @_sym_notify_call(i64 93827664035920) #4, !dbg !44
  tail call void @_sym_set_parameter_expression(i8 0, ptr %3) #4, !dbg !44
  tail call void @_sym_set_return_expression(ptr null) #4, !dbg !44
  %16 = tail call i32 @step1(ptr noundef %0) #4, !dbg !44
  tail call void @_sym_notify_ret(i64 93827664035920) #4, !dbg !44
  %17 = tail call ptr @_sym_get_return_expression() #4, !dbg !44
  %18 = icmp eq ptr %17, null, !dbg !44
  br i1 %18, label %22, label %19, !dbg !44

19:                                               ; preds = %15
  %20 = tail call ptr @_sym_build_integer(i64 0, i8 32) #4, !dbg !44
  %21 = tail call ptr @_sym_build_equal(ptr nonnull %17, ptr %20) #4, !dbg !44
  br label %22, !dbg !44

22:                                               ; preds = %15, %19
  %23 = phi ptr [ null, %15 ], [ %21, %19 ], !dbg !44
  %24 = icmp eq i32 %16, 0, !dbg !44
  %25 = icmp eq ptr %23, null, !dbg !45
  br i1 %25, label %27, label %26, !dbg !45

26:                                               ; preds = %22
  tail call void @_sym_push_path_constraint(ptr nonnull %23, i1 %24, i64 -6339501747245376080) #4, !dbg !45
  br label %27, !dbg !45

27:                                               ; preds = %22, %26
  br i1 %24, label %45, label %28, !dbg !45

28:                                               ; preds = %27
  tail call void @_sym_notify_basic_block(i64 93827664034992) #4, !dbg !46
  tail call void @_sym_notify_call(i64 93827664038128) #4, !dbg !46
  tail call void @_sym_set_parameter_expression(i8 0, ptr %3) #4, !dbg !46
  tail call void @_sym_set_return_expression(ptr null) #4, !dbg !46
  %29 = tail call i32 @step2(ptr noundef %0) #4, !dbg !46
  tail call void @_sym_notify_ret(i64 93827664038128) #4, !dbg !45
  %30 = tail call ptr @_sym_get_return_expression() #4, !dbg !45
  %31 = icmp eq ptr %30, null, !dbg !45
  br i1 %31, label %35, label %32, !dbg !45

32:                                               ; preds = %28
  %33 = tail call ptr @_sym_build_integer(i64 0, i8 32) #4, !dbg !45
  %34 = tail call ptr @_sym_build_not_equal(ptr nonnull %30, ptr %33) #4, !dbg !45
  br label %35, !dbg !45

35:                                               ; preds = %28, %32
  %36 = phi ptr [ null, %28 ], [ %34, %32 ], !dbg !45
  %37 = icmp ne i32 %29, 0, !dbg !45
  %38 = icmp eq ptr %36, null, !dbg !45
  br i1 %38, label %42, label %39, !dbg !45

39:                                               ; preds = %35
  %40 = tail call ptr @_sym_build_bool_to_bit(ptr nonnull %36) #4, !dbg !45
  %41 = tail call ptr @_sym_build_zext(ptr %40, i8 31) #4, !dbg !45
  br label %42, !dbg !45

42:                                               ; preds = %35, %39
  %43 = phi ptr [ null, %35 ], [ %41, %39 ], !dbg !45
  %44 = zext i1 %37 to i32, !dbg !45
  br label %45

45:                                               ; preds = %27, %42, %14
  %46 = phi ptr [ null, %14 ], [ null, %27 ], [ %43, %42 ], !dbg !42
  %47 = phi i32 [ 0, %14 ], [ 0, %27 ], [ %44, %42 ], !dbg !42
  tail call void @_sym_notify_basic_block(i64 93827663553456) #4, !dbg !47
  tail call void @_sym_set_return_expression(ptr %46) #4, !dbg !47
  ret i32 %47, !dbg !47
}

declare !dbg !48 i32 @step1(ptr noundef) local_unnamed_addr #1

declare !dbg !53 i32 @step2(ptr noundef) local_unnamed_addr #1

declare void @_sym_initialize() local_unnamed_addr

; Function Attrs: nounwind uwtable
define internal void @__sym_ctor() #2 {
  tail call void @_sym_initialize() #4
  ret void
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.value(metadata, metadata, metadata) #3

declare ptr @_sym_build_integer(i64, i8)

declare ptr @_sym_build_zext(ptr, i8)

declare ptr @_sym_build_bool_to_bit(ptr)

declare void @_sym_push_path_constraint(ptr, i1, i64)

declare void @_sym_set_parameter_expression(i8, ptr)

declare ptr @_sym_get_parameter_expression(i8)

declare void @_sym_set_return_expression(ptr)

declare ptr @_sym_get_return_expression()

declare ptr @_sym_build_equal(ptr, ptr)

declare ptr @_sym_build_not_equal(ptr, ptr)

declare ptr @_sym_build_unsigned_less_than(ptr, ptr)

declare void @_sym_notify_call(i64)

declare void @_sym_notify_ret(i64)

declare void @_sym_notify_basic_block(i64)

attributes #0 = { nounwind uwtable "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #2 = { nounwind uwtable }
attributes #3 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #4 = { nounwind }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!15, !16, !17, !18, !19, !20, !21}
!llvm.ident = !{!22}

!0 = distinct !DICompileUnit(language: DW_LANG_C11, file: !1, producer: "Ubuntu clang version 18.1.8 (++20240731025043+3b5b5c1ec4a3-1~exp1~20240731145144.92)", isOptimized: true, flags: "/usr/lib/llvm-18/bin/clang -o test-harness.ll -S -emit-llvm -g test-harness.c -g -O3 -funroll-loops -D FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1 -fpass-plugin=/home/procfs/CRS-multilang/uniafl/src/concolic/executor/symcc/prebuild/symcc-pass/build/libsymcc.so -lpthread -lm -lrt -ldl -L/home/procfs/CRS-multilang/uniafl/src/concolic/executor/symcc/prebuild/concolic_executor -lsymcc-rt -Wl,-rpath,/home/procfs/CRS-multilang/uniafl/src/concolic/executor/symcc/prebuild/concolic_executor -Qunused-arguments", runtimeVersion: 0, emissionKind: FullDebug, retainedTypes: !2, splitDebugInlining: false, nameTableKind: None)
!1 = !DIFile(filename: "test-harness.c", directory: "/home/procfs/CRS-multilang/uniafl/src/concolic/executor/symcc/test-harness", checksumkind: CSK_MD5, checksum: "330c0e9931f3f08ad319e8eb49fdcb1f")
!2 = !{!3}
!3 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!4 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "MyStruct", file: !5, line: 1, size: 160, elements: !6)
!5 = !DIFile(filename: "./common.h", directory: "/home/procfs/CRS-multilang/uniafl/src/concolic/executor/symcc/test-harness", checksumkind: CSK_MD5, checksum: "a45836d4a347a3a6990aec16c2156e4d")
!6 = !{!7, !9, !10}
!7 = !DIDerivedType(tag: DW_TAG_member, name: "x", scope: !4, file: !5, line: 2, baseType: !8, size: 32)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !DIDerivedType(tag: DW_TAG_member, name: "y", scope: !4, file: !5, line: 3, baseType: !8, size: 32, offset: 32)
!10 = !DIDerivedType(tag: DW_TAG_member, name: "z", scope: !4, file: !5, line: 4, baseType: !11, size: 80, offset: 64)
!11 = !DICompositeType(tag: DW_TAG_array_type, baseType: !12, size: 80, elements: !13)
!12 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!13 = !{!14}
!14 = !DISubrange(count: 10)
!15 = !{i32 7, !"Dwarf Version", i32 5}
!16 = !{i32 2, !"Debug Info Version", i32 3}
!17 = !{i32 1, !"wchar_size", i32 4}
!18 = !{i32 8, !"PIC Level", i32 2}
!19 = !{i32 7, !"PIE Level", i32 2}
!20 = !{i32 7, !"uwtable", i32 2}
!21 = !{i32 7, !"debug-info-assignment-tracking", i1 true}
!22 = !{!"Ubuntu clang version 18.1.8 (++20240731025043+3b5b5c1ec4a3-1~exp1~20240731145144.92)"}
!23 = distinct !DISubprogram(name: "LLVMFuzzerTestOneInput", scope: !1, file: !1, line: 5, type: !24, scopeLine: 5, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, retainedNodes: !36)
!24 = !DISubroutineType(types: !25)
!25 = !{!8, !26, !33}
!26 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !27, size: 64)
!27 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !28)
!28 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint8_t", file: !29, line: 24, baseType: !30)
!29 = !DIFile(filename: "/usr/include/x86_64-linux-gnu/bits/stdint-uintn.h", directory: "", checksumkind: CSK_MD5, checksum: "256fcabbefa27ca8cf5e6d37525e6e16")
!30 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint8_t", file: !31, line: 38, baseType: !32)
!31 = !DIFile(filename: "/usr/include/x86_64-linux-gnu/bits/types.h", directory: "", checksumkind: CSK_MD5, checksum: "e1865d9fe29fe1b5ced550b7ba458f9e")
!32 = !DIBasicType(name: "unsigned char", size: 8, encoding: DW_ATE_unsigned_char)
!33 = !DIDerivedType(tag: DW_TAG_typedef, name: "size_t", file: !34, line: 18, baseType: !35)
!34 = !DIFile(filename: "/usr/lib/llvm-18/lib/clang/18/include/__stddef_size_t.h", directory: "", checksumkind: CSK_MD5, checksum: "2c44e821a2b1951cde2eb0fb2e656867")
!35 = !DIBasicType(name: "unsigned long", size: 64, encoding: DW_ATE_unsigned)
!36 = !{!37, !38, !39}
!37 = !DILocalVariable(name: "data", arg: 1, scope: !23, file: !1, line: 5, type: !26)
!38 = !DILocalVariable(name: "size", arg: 2, scope: !23, file: !1, line: 5, type: !33)
!39 = !DILocalVariable(name: "s", scope: !23, file: !1, line: 8, type: !3)
!40 = !DILocation(line: 6, column: 12, scope: !41)
!41 = distinct !DILexicalBlock(scope: !23, file: !1, line: 6, column: 7)
!42 = !DILocation(line: 0, scope: !23)
!43 = !DILocation(line: 6, column: 7, scope: !23)
!44 = !DILocation(line: 9, column: 10, scope: !23)
!45 = !DILocation(line: 9, column: 19, scope: !23)
!46 = !DILocation(line: 9, column: 22, scope: !23)
!47 = !DILocation(line: 10, column: 1, scope: !23)
!48 = !DISubprogram(name: "step1", scope: !5, file: !5, line: 7, type: !49, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!49 = !DISubroutineType(types: !50)
!50 = !{!8, !51}
!51 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !52, size: 64)
!52 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !4)
!53 = !DISubprogram(name: "step2", scope: !5, file: !5, line: 8, type: !49, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
