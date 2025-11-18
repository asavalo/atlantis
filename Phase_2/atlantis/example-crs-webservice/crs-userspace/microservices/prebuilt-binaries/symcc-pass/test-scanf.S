
test-scanf:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <_init>:
    1000:	f3 0f 1e fa          	endbr64
    1004:	48 83 ec 08          	sub    $0x8,%rsp
    1008:	48 8b 05 b9 3f 00 00 	mov    0x3fb9(%rip),%rax        # 4fc8 <__gmon_start__@Base>
    100f:	48 85 c0             	test   %rax,%rax
    1012:	74 02                	je     1016 <_init+0x16>
    1014:	ff d0                	call   *%rax
    1016:	48 83 c4 08          	add    $0x8,%rsp
    101a:	c3                   	ret

Disassembly of section .plt:

0000000000001020 <printf@plt-0x10>:
    1020:	ff 35 ca 3f 00 00    	push   0x3fca(%rip)        # 4ff0 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	ff 25 cc 3f 00 00    	jmp    *0x3fcc(%rip)        # 4ff8 <_GLOBAL_OFFSET_TABLE_+0x10>
    102c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000001030 <printf@plt>:
    1030:	ff 25 ca 3f 00 00    	jmp    *0x3fca(%rip)        # 5000 <printf@GLIBC_2.2.5>
    1036:	68 00 00 00 00       	push   $0x0
    103b:	e9 e0 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001040 <fprintf@plt>:
    1040:	ff 25 c2 3f 00 00    	jmp    *0x3fc2(%rip)        # 5008 <fprintf@GLIBC_2.2.5>
    1046:	68 01 00 00 00       	push   $0x1
    104b:	e9 d0 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001050 <_sym_set_return_expression@plt>:
    1050:	ff 25 ba 3f 00 00    	jmp    *0x3fba(%rip)        # 5010 <_sym_set_return_expression@Base>
    1056:	68 02 00 00 00       	push   $0x2
    105b:	e9 c0 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001060 <_sym_build_mul@plt>:
    1060:	ff 25 b2 3f 00 00    	jmp    *0x3fb2(%rip)        # 5018 <_sym_build_mul@Base>
    1066:	68 03 00 00 00       	push   $0x3
    106b:	e9 b0 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001070 <__isoc99_scanf_symbolized_vararg@plt>:
    1070:	ff 25 aa 3f 00 00    	jmp    *0x3faa(%rip)        # 5020 <__isoc99_scanf_symbolized_vararg@Base>
    1076:	68 04 00 00 00       	push   $0x4
    107b:	e9 a0 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001080 <_sym_build_integer@plt>:
    1080:	ff 25 a2 3f 00 00    	jmp    *0x3fa2(%rip)        # 5028 <_sym_build_integer@Base>
    1086:	68 05 00 00 00       	push   $0x5
    108b:	e9 90 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001090 <_sym_get_return_expression@plt>:
    1090:	ff 25 9a 3f 00 00    	jmp    *0x3f9a(%rip)        # 5030 <_sym_get_return_expression@Base>
    1096:	68 06 00 00 00       	push   $0x6
    109b:	e9 80 ff ff ff       	jmp    1020 <_init+0x20>

00000000000010a0 <_sym_build_not_equal@plt>:
    10a0:	ff 25 92 3f 00 00    	jmp    *0x3f92(%rip)        # 5038 <_sym_build_not_equal@Base>
    10a6:	68 07 00 00 00       	push   $0x7
    10ab:	e9 70 ff ff ff       	jmp    1020 <_init+0x20>

00000000000010b0 <_sym_notify_ret@plt>:
    10b0:	ff 25 8a 3f 00 00    	jmp    *0x3f8a(%rip)        # 5040 <_sym_notify_ret@Base>
    10b6:	68 08 00 00 00       	push   $0x8
    10bb:	e9 60 ff ff ff       	jmp    1020 <_init+0x20>

00000000000010c0 <exit@plt>:
    10c0:	ff 25 82 3f 00 00    	jmp    *0x3f82(%rip)        # 5048 <exit@GLIBC_2.2.5>
    10c6:	68 09 00 00 00       	push   $0x9
    10cb:	e9 50 ff ff ff       	jmp    1020 <_init+0x20>

00000000000010d0 <_sym_build_sub@plt>:
    10d0:	ff 25 7a 3f 00 00    	jmp    *0x3f7a(%rip)        # 5050 <_sym_build_sub@Base>
    10d6:	68 0a 00 00 00       	push   $0xa
    10db:	e9 40 ff ff ff       	jmp    1020 <_init+0x20>

00000000000010e0 <_sym_build_add@plt>:
    10e0:	ff 25 72 3f 00 00    	jmp    *0x3f72(%rip)        # 5058 <_sym_build_add@Base>
    10e6:	68 0b 00 00 00       	push   $0xb
    10eb:	e9 30 ff ff ff       	jmp    1020 <_init+0x20>

00000000000010f0 <_sym_notify_function@plt>:
    10f0:	ff 25 6a 3f 00 00    	jmp    *0x3f6a(%rip)        # 5060 <_sym_notify_function@Base>
    10f6:	68 0c 00 00 00       	push   $0xc
    10fb:	e9 20 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001100 <_sym_build_signed_div@plt>:
    1100:	ff 25 62 3f 00 00    	jmp    *0x3f62(%rip)        # 5068 <_sym_build_signed_div@Base>
    1106:	68 0d 00 00 00       	push   $0xd
    110b:	e9 10 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001110 <_sym_initialize@plt>:
    1110:	ff 25 5a 3f 00 00    	jmp    *0x3f5a(%rip)        # 5070 <_sym_initialize@Base>
    1116:	68 0e 00 00 00       	push   $0xe
    111b:	e9 00 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001120 <_sym_read_memory@plt>:
    1120:	ff 25 52 3f 00 00    	jmp    *0x3f52(%rip)        # 5078 <_sym_read_memory@Base>
    1126:	68 0f 00 00 00       	push   $0xf
    112b:	e9 f0 fe ff ff       	jmp    1020 <_init+0x20>

0000000000001130 <_sym_push_path_constraint@plt>:
    1130:	ff 25 4a 3f 00 00    	jmp    *0x3f4a(%rip)        # 5080 <_sym_push_path_constraint@Base>
    1136:	68 10 00 00 00       	push   $0x10
    113b:	e9 e0 fe ff ff       	jmp    1020 <_init+0x20>

0000000000001140 <_sym_notify_basic_block@plt>:
    1140:	ff 25 42 3f 00 00    	jmp    *0x3f42(%rip)        # 5088 <_sym_notify_basic_block@Base>
    1146:	68 11 00 00 00       	push   $0x11
    114b:	e9 d0 fe ff ff       	jmp    1020 <_init+0x20>

0000000000001150 <_sym_set_parameter_expression@plt>:
    1150:	ff 25 3a 3f 00 00    	jmp    *0x3f3a(%rip)        # 5090 <_sym_set_parameter_expression@Base>
    1156:	68 12 00 00 00       	push   $0x12
    115b:	e9 c0 fe ff ff       	jmp    1020 <_init+0x20>

0000000000001160 <_sym_notify_call@plt>:
    1160:	ff 25 32 3f 00 00    	jmp    *0x3f32(%rip)        # 5098 <_sym_notify_call@Base>
    1166:	68 13 00 00 00       	push   $0x13
    116b:	e9 b0 fe ff ff       	jmp    1020 <_init+0x20>

0000000000001170 <_sym_write_memory@plt>:
    1170:	ff 25 2a 3f 00 00    	jmp    *0x3f2a(%rip)        # 50a0 <_sym_write_memory@Base>
    1176:	68 14 00 00 00       	push   $0x14
    117b:	e9 a0 fe ff ff       	jmp    1020 <_init+0x20>

Disassembly of section .plt.got:

0000000000001180 <__cxa_finalize@plt>:
    1180:	ff 25 3a 3e 00 00    	jmp    *0x3e3a(%rip)        # 4fc0 <__cxa_finalize@GLIBC_2.2.5>
    1186:	66 90                	xchg   %ax,%ax

Disassembly of section .text:

0000000000001190 <_start>:
    1190:	f3 0f 1e fa          	endbr64
    1194:	31 ed                	xor    %ebp,%ebp
    1196:	49 89 d1             	mov    %rdx,%r9
    1199:	5e                   	pop    %rsi
    119a:	48 89 e2             	mov    %rsp,%rdx
    119d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    11a1:	50                   	push   %rax
    11a2:	54                   	push   %rsp
    11a3:	45 31 c0             	xor    %r8d,%r8d
    11a6:	31 c9                	xor    %ecx,%ecx
    11a8:	48 8d 3d d1 00 00 00 	lea    0xd1(%rip),%rdi        # 1280 <main>
    11af:	ff 15 2b 3e 00 00    	call   *0x3e2b(%rip)        # 4fe0 <__libc_start_main@GLIBC_2.34>
    11b5:	f4                   	hlt
    11b6:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    11bd:	00 00 00 

00000000000011c0 <deregister_tm_clones>:
    11c0:	48 8d 3d f1 3e 00 00 	lea    0x3ef1(%rip),%rdi        # 50b8 <__symcc_func_id.main>
    11c7:	48 8d 05 ea 3e 00 00 	lea    0x3eea(%rip),%rax        # 50b8 <__symcc_func_id.main>
    11ce:	48 39 f8             	cmp    %rdi,%rax
    11d1:	74 15                	je     11e8 <deregister_tm_clones+0x28>
    11d3:	48 8b 05 de 3d 00 00 	mov    0x3dde(%rip),%rax        # 4fb8 <_ITM_deregisterTMCloneTable@Base>
    11da:	48 85 c0             	test   %rax,%rax
    11dd:	74 09                	je     11e8 <deregister_tm_clones+0x28>
    11df:	ff e0                	jmp    *%rax
    11e1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    11e8:	c3                   	ret
    11e9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000011f0 <register_tm_clones>:
    11f0:	48 8d 3d c1 3e 00 00 	lea    0x3ec1(%rip),%rdi        # 50b8 <__symcc_func_id.main>
    11f7:	48 8d 35 ba 3e 00 00 	lea    0x3eba(%rip),%rsi        # 50b8 <__symcc_func_id.main>
    11fe:	48 29 fe             	sub    %rdi,%rsi
    1201:	48 89 f0             	mov    %rsi,%rax
    1204:	48 c1 ee 3f          	shr    $0x3f,%rsi
    1208:	48 c1 f8 03          	sar    $0x3,%rax
    120c:	48 01 c6             	add    %rax,%rsi
    120f:	48 d1 fe             	sar    $1,%rsi
    1212:	74 14                	je     1228 <register_tm_clones+0x38>
    1214:	48 8b 05 bd 3d 00 00 	mov    0x3dbd(%rip),%rax        # 4fd8 <_ITM_registerTMCloneTable@Base>
    121b:	48 85 c0             	test   %rax,%rax
    121e:	74 08                	je     1228 <register_tm_clones+0x38>
    1220:	ff e0                	jmp    *%rax
    1222:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1228:	c3                   	ret
    1229:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001230 <__do_global_dtors_aux>:
    1230:	f3 0f 1e fa          	endbr64
    1234:	80 3d 85 3e 00 00 00 	cmpb   $0x0,0x3e85(%rip)        # 50c0 <completed.0>
    123b:	75 2b                	jne    1268 <__do_global_dtors_aux+0x38>
    123d:	55                   	push   %rbp
    123e:	48 83 3d 7a 3d 00 00 	cmpq   $0x0,0x3d7a(%rip)        # 4fc0 <__cxa_finalize@GLIBC_2.2.5>
    1245:	00 
    1246:	48 89 e5             	mov    %rsp,%rbp
    1249:	74 0c                	je     1257 <__do_global_dtors_aux+0x27>
    124b:	48 8b 3d 5e 3e 00 00 	mov    0x3e5e(%rip),%rdi        # 50b0 <__dso_handle>
    1252:	e8 29 ff ff ff       	call   1180 <__cxa_finalize@plt>
    1257:	e8 64 ff ff ff       	call   11c0 <deregister_tm_clones>
    125c:	c6 05 5d 3e 00 00 01 	movb   $0x1,0x3e5d(%rip)        # 50c0 <completed.0>
    1263:	5d                   	pop    %rbp
    1264:	c3                   	ret
    1265:	0f 1f 00             	nopl   (%rax)
    1268:	c3                   	ret
    1269:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001270 <frame_dummy>:
    1270:	f3 0f 1e fa          	endbr64
    1274:	e9 77 ff ff ff       	jmp    11f0 <register_tm_clones>
    1279:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001280 <main>:
    1280:	55                   	push   %rbp
    1281:	48 89 e5             	mov    %rsp,%rbp
    1284:	48 81 ec c0 01 00 00 	sub    $0x1c0,%rsp
    128b:	48 bf 38 13 df c5 55 	movabs $0x5c55c5df1338,%rdi
    1292:	5c 00 00 
    1295:	e8 56 fe ff ff       	call   10f0 <_sym_notify_function@plt>
    129a:	48 bf 80 4d e4 c5 55 	movabs $0x5c55c5e44d80,%rdi
    12a1:	5c 00 00 
    12a4:	e8 97 fe ff ff       	call   1140 <_sym_notify_basic_block@plt>
    12a9:	48 8d 7d fc          	lea    -0x4(%rbp),%rdi
    12ad:	be 04 00 00 00       	mov    $0x4,%esi
    12b2:	31 c0                	xor    %eax,%eax
    12b4:	89 c2                	mov    %eax,%edx
    12b6:	b9 01 00 00 00       	mov    $0x1,%ecx
    12bb:	e8 b0 fe ff ff       	call   1170 <_sym_write_memory@plt>
    12c0:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    12c7:	48 bf 70 7f f4 c5 55 	movabs $0x5c55c5f47f70,%rdi
    12ce:	5c 00 00 
    12d1:	e8 8a fe ff ff       	call   1160 <_sym_notify_call@plt>
    12d6:	31 ff                	xor    %edi,%edi
    12d8:	31 c0                	xor    %eax,%eax
    12da:	89 c6                	mov    %eax,%esi
    12dc:	e8 6f fe ff ff       	call   1150 <_sym_set_parameter_expression@plt>
    12e1:	bf 01 00 00 00       	mov    $0x1,%edi
    12e6:	31 c0                	xor    %eax,%eax
    12e8:	89 c6                	mov    %eax,%esi
    12ea:	e8 61 fe ff ff       	call   1150 <_sym_set_parameter_expression@plt>
    12ef:	bf 02 00 00 00       	mov    $0x2,%edi
    12f4:	31 c0                	xor    %eax,%eax
    12f6:	89 c6                	mov    %eax,%esi
    12f8:	e8 53 fe ff ff       	call   1150 <_sym_set_parameter_expression@plt>
    12fd:	bf 03 00 00 00       	mov    $0x3,%edi
    1302:	31 c0                	xor    %eax,%eax
    1304:	89 c6                	mov    %eax,%esi
    1306:	e8 45 fe ff ff       	call   1150 <_sym_set_parameter_expression@plt>
    130b:	bf 04 00 00 00       	mov    $0x4,%edi
    1310:	31 c0                	xor    %eax,%eax
    1312:	89 c6                	mov    %eax,%esi
    1314:	e8 37 fe ff ff       	call   1150 <_sym_set_parameter_expression@plt>
    1319:	31 c0                	xor    %eax,%eax
    131b:	89 c7                	mov    %eax,%edi
    131d:	e8 2e fd ff ff       	call   1050 <_sym_set_return_expression@plt>
    1322:	bf 03 00 00 00       	mov    $0x3,%edi
    1327:	48 8d 35 ea 1c 00 00 	lea    0x1cea(%rip),%rsi        # 3018 <_IO_stdin_used+0x18>
    132e:	48 8d 55 f8          	lea    -0x8(%rbp),%rdx
    1332:	48 8d 4d f4          	lea    -0xc(%rbp),%rcx
    1336:	4c 8d 45 f0          	lea    -0x10(%rbp),%r8
    133a:	b0 00                	mov    $0x0,%al
    133c:	e8 2f fd ff ff       	call   1070 <__isoc99_scanf_symbolized_vararg@plt>
    1341:	89 45 cc             	mov    %eax,-0x34(%rbp)
    1344:	48 bf 70 7f f4 c5 55 	movabs $0x5c55c5f47f70,%rdi
    134b:	5c 00 00 
    134e:	e8 5d fd ff ff       	call   10b0 <_sym_notify_ret@plt>
    1353:	e8 38 fd ff ff       	call   1090 <_sym_get_return_expression@plt>
    1358:	48 89 c2             	mov    %rax,%rdx
    135b:	48 8d 7d e8          	lea    -0x18(%rbp),%rdi
    135f:	be 04 00 00 00       	mov    $0x4,%esi
    1364:	b9 01 00 00 00       	mov    $0x1,%ecx
    1369:	e8 02 fe ff ff       	call   1170 <_sym_write_memory@plt>
    136e:	8b 45 cc             	mov    -0x34(%rbp),%eax
    1371:	89 45 e8             	mov    %eax,-0x18(%rbp)
    1374:	48 8d 7d e8          	lea    -0x18(%rbp),%rdi
    1378:	be 04 00 00 00       	mov    $0x4,%esi
    137d:	ba 01 00 00 00       	mov    $0x1,%edx
    1382:	e8 99 fd ff ff       	call   1120 <_sym_read_memory@plt>
    1387:	48 89 c1             	mov    %rax,%rcx
    138a:	48 89 4d d0          	mov    %rcx,-0x30(%rbp)
    138e:	8b 45 e8             	mov    -0x18(%rbp),%eax
    1391:	89 45 dc             	mov    %eax,-0x24(%rbp)
    1394:	31 c0                	xor    %eax,%eax
    1396:	48 39 c8             	cmp    %rcx,%rax
    1399:	0f 94 c1             	sete   %cl
    139c:	80 e1 ff             	and    $0xff,%cl
    139f:	31 c0                	xor    %eax,%eax
    13a1:	f6 c1 01             	test   $0x1,%cl
    13a4:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    13a8:	0f 85 1f 00 00 00    	jne    13cd <main+0x14d>
    13ae:	bf 01 00 00 00       	mov    $0x1,%edi
    13b3:	be 20 00 00 00       	mov    $0x20,%esi
    13b8:	e8 c3 fc ff ff       	call   1080 <_sym_build_integer@plt>
    13bd:	48 8b 7d d0          	mov    -0x30(%rbp),%rdi
    13c1:	48 89 c6             	mov    %rax,%rsi
    13c4:	e8 d7 fc ff ff       	call   10a0 <_sym_build_not_equal@plt>
    13c9:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    13cd:	8b 45 dc             	mov    -0x24(%rbp),%eax
    13d0:	48 8b 4d e0          	mov    -0x20(%rbp),%rcx
    13d4:	48 89 4d c0          	mov    %rcx,-0x40(%rbp)
    13d8:	83 f8 01             	cmp    $0x1,%eax
    13db:	0f 95 c0             	setne  %al
    13de:	88 45 cb             	mov    %al,-0x35(%rbp)
    13e1:	31 c0                	xor    %eax,%eax
    13e3:	48 39 c8             	cmp    %rcx,%rax
    13e6:	0f 84 19 00 00 00    	je     1405 <main+0x185>
    13ec:	48 8b 7d c0          	mov    -0x40(%rbp),%rdi
    13f0:	8a 45 cb             	mov    -0x35(%rbp),%al
    13f3:	0f b6 f0             	movzbl %al,%esi
    13f6:	48 ba 50 4f f7 c5 55 	movabs $0x5c55c5f74f50,%rdx
    13fd:	5c 00 00 
    1400:	e8 2b fd ff ff       	call   1130 <_sym_push_path_constraint@plt>
    1405:	8a 45 cb             	mov    -0x35(%rbp),%al
    1408:	a8 01                	test   $0x1,%al
    140a:	0f 85 05 00 00 00    	jne    1415 <main+0x195>
    1410:	e9 b3 00 00 00       	jmp    14c8 <main+0x248>
    1415:	48 bf 50 4f f7 c5 55 	movabs $0x5c55c5f74f50,%rdi
    141c:	5c 00 00 
    141f:	e8 1c fd ff ff       	call   1140 <_sym_notify_basic_block@plt>
    1424:	48 8b 3d a5 3b 00 00 	mov    0x3ba5(%rip),%rdi        # 4fd0 <stderr@GLIBC_2.2.5>
    142b:	be 08 00 00 00       	mov    $0x8,%esi
    1430:	ba 01 00 00 00       	mov    $0x1,%edx
    1435:	e8 e6 fc ff ff       	call   1120 <_sym_read_memory@plt>
    143a:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
    143e:	48 8b 05 8b 3b 00 00 	mov    0x3b8b(%rip),%rax        # 4fd0 <stderr@GLIBC_2.2.5>
    1445:	48 8b 00             	mov    (%rax),%rax
    1448:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    144c:	48 bf 50 52 f7 c5 55 	movabs $0x5c55c5f75250,%rdi
    1453:	5c 00 00 
    1456:	e8 05 fd ff ff       	call   1160 <_sym_notify_call@plt>
    145b:	48 8b 75 b0          	mov    -0x50(%rbp),%rsi
    145f:	31 ff                	xor    %edi,%edi
    1461:	e8 ea fc ff ff       	call   1150 <_sym_set_parameter_expression@plt>
    1466:	bf 01 00 00 00       	mov    $0x1,%edi
    146b:	31 c0                	xor    %eax,%eax
    146d:	89 c6                	mov    %eax,%esi
    146f:	e8 dc fc ff ff       	call   1150 <_sym_set_parameter_expression@plt>
    1474:	48 8b 7d b8          	mov    -0x48(%rbp),%rdi
    1478:	48 8d 35 a3 1b 00 00 	lea    0x1ba3(%rip),%rsi        # 3022 <_IO_stdin_used+0x22>
    147f:	b0 00                	mov    $0x0,%al
    1481:	e8 ba fb ff ff       	call   1040 <fprintf@plt>
    1486:	48 bf 50 52 f7 c5 55 	movabs $0x5c55c5f75250,%rdi
    148d:	5c 00 00 
    1490:	e8 1b fc ff ff       	call   10b0 <_sym_notify_ret@plt>
    1495:	48 bf f0 60 f7 c5 55 	movabs $0x5c55c5f760f0,%rdi
    149c:	5c 00 00 
    149f:	e8 bc fc ff ff       	call   1160 <_sym_notify_call@plt>
    14a4:	31 ff                	xor    %edi,%edi
    14a6:	31 c0                	xor    %eax,%eax
    14a8:	89 c6                	mov    %eax,%esi
    14aa:	e8 a1 fc ff ff       	call   1150 <_sym_set_parameter_expression@plt>
    14af:	bf ff ff ff ff       	mov    $0xffffffff,%edi
    14b4:	e8 07 fc ff ff       	call   10c0 <exit@plt>
    14b9:	48 bf f0 60 f7 c5 55 	movabs $0x5c55c5f760f0,%rdi
    14c0:	5c 00 00 
    14c3:	e8 e8 fb ff ff       	call   10b0 <_sym_notify_ret@plt>
    14c8:	48 bf a0 4f f7 c5 55 	movabs $0x5c55c5f74fa0,%rdi
    14cf:	5c 00 00 
    14d2:	e8 69 fc ff ff       	call   1140 <_sym_notify_basic_block@plt>
    14d7:	48 8d 7d f8          	lea    -0x8(%rbp),%rdi
    14db:	be 04 00 00 00       	mov    $0x4,%esi
    14e0:	ba 01 00 00 00       	mov    $0x1,%edx
    14e5:	e8 36 fc ff ff       	call   1120 <_sym_read_memory@plt>
    14ea:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
    14ee:	8b 45 f8             	mov    -0x8(%rbp),%eax
    14f1:	ff c8                	dec    %eax
    14f3:	89 c1                	mov    %eax,%ecx
    14f5:	48 89 4d a8          	mov    %rcx,-0x58(%rbp)
    14f9:	83 e8 04             	sub    $0x4,%eax
    14fc:	0f 87 06 0a 00 00    	ja     1f08 <main+0xc88>
    1502:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    1506:	48 8d 0d f7 1a 00 00 	lea    0x1af7(%rip),%rcx        # 3004 <_IO_stdin_used+0x4>
    150d:	48 63 04 81          	movslq (%rcx,%rax,4),%rax
    1511:	48 01 c8             	add    %rcx,%rax
    1514:	ff e0                	jmp    *%rax
    1516:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    151a:	48 83 f8 00          	cmp    $0x0,%rax
    151e:	0f 84 c8 00 00 00    	je     15ec <main+0x36c>
    1524:	bf 02 00 00 00       	mov    $0x2,%edi
    1529:	be 20 00 00 00       	mov    $0x20,%esi
    152e:	e8 4d fb ff ff       	call   1080 <_sym_build_integer@plt>
    1533:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    1537:	48 89 c6             	mov    %rax,%rsi
    153a:	e8 61 fb ff ff       	call   10a0 <_sym_build_not_equal@plt>
    153f:	48 89 c7             	mov    %rax,%rdi
    1542:	be 01 00 00 00       	mov    $0x1,%esi
    1547:	48 ba 60 97 ed c5 55 	movabs $0x5c55c5ed9760,%rdx
    154e:	5c 00 00 
    1551:	e8 da fb ff ff       	call   1130 <_sym_push_path_constraint@plt>
    1556:	bf 03 00 00 00       	mov    $0x3,%edi
    155b:	be 20 00 00 00       	mov    $0x20,%esi
    1560:	e8 1b fb ff ff       	call   1080 <_sym_build_integer@plt>
    1565:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    1569:	48 89 c6             	mov    %rax,%rsi
    156c:	e8 2f fb ff ff       	call   10a0 <_sym_build_not_equal@plt>
    1571:	48 89 c7             	mov    %rax,%rdi
    1574:	be 01 00 00 00       	mov    $0x1,%esi
    1579:	48 ba 60 97 ed c5 55 	movabs $0x5c55c5ed9760,%rdx
    1580:	5c 00 00 
    1583:	e8 a8 fb ff ff       	call   1130 <_sym_push_path_constraint@plt>
    1588:	bf 04 00 00 00       	mov    $0x4,%edi
    158d:	be 20 00 00 00       	mov    $0x20,%esi
    1592:	e8 e9 fa ff ff       	call   1080 <_sym_build_integer@plt>
    1597:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    159b:	48 89 c6             	mov    %rax,%rsi
    159e:	e8 fd fa ff ff       	call   10a0 <_sym_build_not_equal@plt>
    15a3:	48 89 c7             	mov    %rax,%rdi
    15a6:	be 01 00 00 00       	mov    $0x1,%esi
    15ab:	48 ba 60 97 ed c5 55 	movabs $0x5c55c5ed9760,%rdx
    15b2:	5c 00 00 
    15b5:	e8 76 fb ff ff       	call   1130 <_sym_push_path_constraint@plt>
    15ba:	bf 05 00 00 00       	mov    $0x5,%edi
    15bf:	be 20 00 00 00       	mov    $0x20,%esi
    15c4:	e8 b7 fa ff ff       	call   1080 <_sym_build_integer@plt>
    15c9:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    15cd:	48 89 c6             	mov    %rax,%rsi
    15d0:	e8 cb fa ff ff       	call   10a0 <_sym_build_not_equal@plt>
    15d5:	48 89 c7             	mov    %rax,%rdi
    15d8:	be 01 00 00 00       	mov    $0x1,%esi
    15dd:	48 ba 60 97 ed c5 55 	movabs $0x5c55c5ed9760,%rdx
    15e4:	5c 00 00 
    15e7:	e8 44 fb ff ff       	call   1130 <_sym_push_path_constraint@plt>
    15ec:	e9 00 00 00 00       	jmp    15f1 <main+0x371>
    15f1:	48 bf f0 65 f7 c5 55 	movabs $0x5c55c5f765f0,%rdi
    15f8:	5c 00 00 
    15fb:	e8 40 fb ff ff       	call   1140 <_sym_notify_basic_block@plt>
    1600:	48 8d 7d f4          	lea    -0xc(%rbp),%rdi
    1604:	be 04 00 00 00       	mov    $0x4,%esi
    1609:	ba 01 00 00 00       	mov    $0x1,%edx
    160e:	e8 0d fb ff ff       	call   1120 <_sym_read_memory@plt>
    1613:	48 89 45 80          	mov    %rax,-0x80(%rbp)
    1617:	8b 45 f4             	mov    -0xc(%rbp),%eax
    161a:	89 85 7c ff ff ff    	mov    %eax,-0x84(%rbp)
    1620:	48 8d 7d f0          	lea    -0x10(%rbp),%rdi
    1624:	be 04 00 00 00       	mov    $0x4,%esi
    1629:	ba 01 00 00 00       	mov    $0x1,%edx
    162e:	e8 ed fa ff ff       	call   1120 <_sym_read_memory@plt>
    1633:	48 8b 4d 80          	mov    -0x80(%rbp),%rcx
    1637:	48 89 c2             	mov    %rax,%rdx
    163a:	48 89 55 88          	mov    %rdx,-0x78(%rbp)
    163e:	8b 45 f0             	mov    -0x10(%rbp),%eax
    1641:	89 45 90             	mov    %eax,-0x70(%rbp)
    1644:	31 c0                	xor    %eax,%eax
    1646:	48 39 c8             	cmp    %rcx,%rax
    1649:	0f 94 c1             	sete   %cl
    164c:	88 4d 96             	mov    %cl,-0x6a(%rbp)
    164f:	31 c0                	xor    %eax,%eax
    1651:	48 39 d0             	cmp    %rdx,%rax
    1654:	0f 94 c0             	sete   %al
    1657:	88 45 97             	mov    %al,-0x69(%rbp)
    165a:	20 c1                	and    %al,%cl
    165c:	31 c0                	xor    %eax,%eax
    165e:	f6 c1 01             	test   $0x1,%cl
    1661:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    1665:	0f 85 90 00 00 00    	jne    16fb <main+0x47b>
    166b:	48 8b 45 80          	mov    -0x80(%rbp),%rax
    166f:	8a 4d 96             	mov    -0x6a(%rbp),%cl
    1672:	f6 c1 01             	test   $0x1,%cl
    1675:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
    167c:	0f 85 05 00 00 00    	jne    1687 <main+0x407>
    1682:	e9 1b 00 00 00       	jmp    16a2 <main+0x422>
    1687:	8b 85 7c ff ff ff    	mov    -0x84(%rbp),%eax
    168d:	89 c0                	mov    %eax,%eax
    168f:	89 c7                	mov    %eax,%edi
    1691:	be 20 00 00 00       	mov    $0x20,%esi
    1696:	e8 e5 f9 ff ff       	call   1080 <_sym_build_integer@plt>
    169b:	48 89 85 70 ff ff ff 	mov    %rax,-0x90(%rbp)
    16a2:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    16a6:	8a 4d 97             	mov    -0x69(%rbp),%cl
    16a9:	48 8b 95 70 ff ff ff 	mov    -0x90(%rbp),%rdx
    16b0:	48 89 95 60 ff ff ff 	mov    %rdx,-0xa0(%rbp)
    16b7:	f6 c1 01             	test   $0x1,%cl
    16ba:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
    16c1:	0f 85 05 00 00 00    	jne    16cc <main+0x44c>
    16c7:	e9 18 00 00 00       	jmp    16e4 <main+0x464>
    16cc:	8b 45 90             	mov    -0x70(%rbp),%eax
    16cf:	89 c0                	mov    %eax,%eax
    16d1:	89 c7                	mov    %eax,%edi
    16d3:	be 20 00 00 00       	mov    $0x20,%esi
    16d8:	e8 a3 f9 ff ff       	call   1080 <_sym_build_integer@plt>
    16dd:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
    16e4:	48 8b bd 60 ff ff ff 	mov    -0xa0(%rbp),%rdi
    16eb:	48 8b b5 68 ff ff ff 	mov    -0x98(%rbp),%rsi
    16f2:	e8 69 f9 ff ff       	call   1060 <_sym_build_mul@plt>
    16f7:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    16fb:	8b 4d 90             	mov    -0x70(%rbp),%ecx
    16fe:	8b 85 7c ff ff ff    	mov    -0x84(%rbp),%eax
    1704:	48 8b 55 98          	mov    -0x68(%rbp),%rdx
    1708:	0f af c1             	imul   %ecx,%eax
    170b:	89 85 5c ff ff ff    	mov    %eax,-0xa4(%rbp)
    1711:	48 8d 7d ec          	lea    -0x14(%rbp),%rdi
    1715:	be 04 00 00 00       	mov    $0x4,%esi
    171a:	b9 01 00 00 00       	mov    $0x1,%ecx
    171f:	e8 4c fa ff ff       	call   1170 <_sym_write_memory@plt>
    1724:	8b 85 5c ff ff ff    	mov    -0xa4(%rbp),%eax
    172a:	89 45 ec             	mov    %eax,-0x14(%rbp)
    172d:	e9 db 00 00 00       	jmp    180d <main+0x58d>
    1732:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    1736:	48 83 f8 00          	cmp    $0x0,%rax
    173a:	0f 84 c8 00 00 00    	je     1808 <main+0x588>
    1740:	bf 01 00 00 00       	mov    $0x1,%edi
    1745:	be 20 00 00 00       	mov    $0x20,%esi
    174a:	e8 31 f9 ff ff       	call   1080 <_sym_build_integer@plt>
    174f:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    1753:	48 89 c6             	mov    %rax,%rsi
    1756:	e8 45 f9 ff ff       	call   10a0 <_sym_build_not_equal@plt>
    175b:	48 89 c7             	mov    %rax,%rdi
    175e:	be 01 00 00 00       	mov    $0x1,%esi
    1763:	48 ba 00 a0 f5 c5 55 	movabs $0x5c55c5f5a000,%rdx
    176a:	5c 00 00 
    176d:	e8 be f9 ff ff       	call   1130 <_sym_push_path_constraint@plt>
    1772:	bf 03 00 00 00       	mov    $0x3,%edi
    1777:	be 20 00 00 00       	mov    $0x20,%esi
    177c:	e8 ff f8 ff ff       	call   1080 <_sym_build_integer@plt>
    1781:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    1785:	48 89 c6             	mov    %rax,%rsi
    1788:	e8 13 f9 ff ff       	call   10a0 <_sym_build_not_equal@plt>
    178d:	48 89 c7             	mov    %rax,%rdi
    1790:	be 01 00 00 00       	mov    $0x1,%esi
    1795:	48 ba 00 a0 f5 c5 55 	movabs $0x5c55c5f5a000,%rdx
    179c:	5c 00 00 
    179f:	e8 8c f9 ff ff       	call   1130 <_sym_push_path_constraint@plt>
    17a4:	bf 04 00 00 00       	mov    $0x4,%edi
    17a9:	be 20 00 00 00       	mov    $0x20,%esi
    17ae:	e8 cd f8 ff ff       	call   1080 <_sym_build_integer@plt>
    17b3:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    17b7:	48 89 c6             	mov    %rax,%rsi
    17ba:	e8 e1 f8 ff ff       	call   10a0 <_sym_build_not_equal@plt>
    17bf:	48 89 c7             	mov    %rax,%rdi
    17c2:	be 01 00 00 00       	mov    $0x1,%esi
    17c7:	48 ba 00 a0 f5 c5 55 	movabs $0x5c55c5f5a000,%rdx
    17ce:	5c 00 00 
    17d1:	e8 5a f9 ff ff       	call   1130 <_sym_push_path_constraint@plt>
    17d6:	bf 05 00 00 00       	mov    $0x5,%edi
    17db:	be 20 00 00 00       	mov    $0x20,%esi
    17e0:	e8 9b f8 ff ff       	call   1080 <_sym_build_integer@plt>
    17e5:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    17e9:	48 89 c6             	mov    %rax,%rsi
    17ec:	e8 af f8 ff ff       	call   10a0 <_sym_build_not_equal@plt>
    17f1:	48 89 c7             	mov    %rax,%rdi
    17f4:	be 01 00 00 00       	mov    $0x1,%esi
    17f9:	48 ba 00 a0 f5 c5 55 	movabs $0x5c55c5f5a000,%rdx
    1800:	5c 00 00 
    1803:	e8 28 f9 ff ff       	call   1130 <_sym_push_path_constraint@plt>
    1808:	e9 00 00 00 00       	jmp    180d <main+0x58d>
    180d:	48 bf 70 68 f7 c5 55 	movabs $0x5c55c5f76870,%rdi
    1814:	5c 00 00 
    1817:	e8 24 f9 ff ff       	call   1140 <_sym_notify_basic_block@plt>
    181c:	48 8d 7d f4          	lea    -0xc(%rbp),%rdi
    1820:	be 04 00 00 00       	mov    $0x4,%esi
    1825:	ba 01 00 00 00       	mov    $0x1,%edx
    182a:	e8 f1 f8 ff ff       	call   1120 <_sym_read_memory@plt>
    182f:	48 89 85 38 ff ff ff 	mov    %rax,-0xc8(%rbp)
    1836:	8b 45 f4             	mov    -0xc(%rbp),%eax
    1839:	89 85 34 ff ff ff    	mov    %eax,-0xcc(%rbp)
    183f:	48 8d 7d f0          	lea    -0x10(%rbp),%rdi
    1843:	be 04 00 00 00       	mov    $0x4,%esi
    1848:	ba 01 00 00 00       	mov    $0x1,%edx
    184d:	e8 ce f8 ff ff       	call   1120 <_sym_read_memory@plt>
    1852:	48 8b 8d 38 ff ff ff 	mov    -0xc8(%rbp),%rcx
    1859:	48 89 c2             	mov    %rax,%rdx
    185c:	48 89 95 40 ff ff ff 	mov    %rdx,-0xc0(%rbp)
    1863:	8b 45 f0             	mov    -0x10(%rbp),%eax
    1866:	89 85 48 ff ff ff    	mov    %eax,-0xb8(%rbp)
    186c:	31 c0                	xor    %eax,%eax
    186e:	48 39 c8             	cmp    %rcx,%rax
    1871:	0f 94 c1             	sete   %cl
    1874:	88 8d 4e ff ff ff    	mov    %cl,-0xb2(%rbp)
    187a:	31 c0                	xor    %eax,%eax
    187c:	48 39 d0             	cmp    %rdx,%rax
    187f:	0f 94 c0             	sete   %al
    1882:	88 85 4f ff ff ff    	mov    %al,-0xb1(%rbp)
    1888:	20 c1                	and    %al,%cl
    188a:	31 c0                	xor    %eax,%eax
    188c:	f6 c1 01             	test   $0x1,%cl
    188f:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    1896:	0f 85 a2 00 00 00    	jne    193e <main+0x6be>
    189c:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    18a3:	8a 8d 4e ff ff ff    	mov    -0xb2(%rbp),%cl
    18a9:	f6 c1 01             	test   $0x1,%cl
    18ac:	48 89 85 28 ff ff ff 	mov    %rax,-0xd8(%rbp)
    18b3:	0f 85 05 00 00 00    	jne    18be <main+0x63e>
    18b9:	e9 1b 00 00 00       	jmp    18d9 <main+0x659>
    18be:	8b 85 34 ff ff ff    	mov    -0xcc(%rbp),%eax
    18c4:	89 c0                	mov    %eax,%eax
    18c6:	89 c7                	mov    %eax,%edi
    18c8:	be 20 00 00 00       	mov    $0x20,%esi
    18cd:	e8 ae f7 ff ff       	call   1080 <_sym_build_integer@plt>
    18d2:	48 89 85 28 ff ff ff 	mov    %rax,-0xd8(%rbp)
    18d9:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
    18e0:	8a 8d 4f ff ff ff    	mov    -0xb1(%rbp),%cl
    18e6:	48 8b 95 28 ff ff ff 	mov    -0xd8(%rbp),%rdx
    18ed:	48 89 95 18 ff ff ff 	mov    %rdx,-0xe8(%rbp)
    18f4:	f6 c1 01             	test   $0x1,%cl
    18f7:	48 89 85 20 ff ff ff 	mov    %rax,-0xe0(%rbp)
    18fe:	0f 85 05 00 00 00    	jne    1909 <main+0x689>
    1904:	e9 1b 00 00 00       	jmp    1924 <main+0x6a4>
    1909:	8b 85 48 ff ff ff    	mov    -0xb8(%rbp),%eax
    190f:	89 c0                	mov    %eax,%eax
    1911:	89 c7                	mov    %eax,%edi
    1913:	be 20 00 00 00       	mov    $0x20,%esi
    1918:	e8 63 f7 ff ff       	call   1080 <_sym_build_integer@plt>
    191d:	48 89 85 20 ff ff ff 	mov    %rax,-0xe0(%rbp)
    1924:	48 8b bd 18 ff ff ff 	mov    -0xe8(%rbp),%rdi
    192b:	48 8b b5 20 ff ff ff 	mov    -0xe0(%rbp),%rsi
    1932:	e8 a9 f7 ff ff       	call   10e0 <_sym_build_add@plt>
    1937:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
    193e:	8b 8d 48 ff ff ff    	mov    -0xb8(%rbp),%ecx
    1944:	8b 85 34 ff ff ff    	mov    -0xcc(%rbp),%eax
    194a:	48 8b 95 50 ff ff ff 	mov    -0xb0(%rbp),%rdx
    1951:	01 c8                	add    %ecx,%eax
    1953:	89 85 14 ff ff ff    	mov    %eax,-0xec(%rbp)
    1959:	48 8d 7d ec          	lea    -0x14(%rbp),%rdi
    195d:	be 04 00 00 00       	mov    $0x4,%esi
    1962:	b9 01 00 00 00       	mov    $0x1,%ecx
    1967:	e8 04 f8 ff ff       	call   1170 <_sym_write_memory@plt>
    196c:	8b 85 14 ff ff ff    	mov    -0xec(%rbp),%eax
    1972:	89 45 ec             	mov    %eax,-0x14(%rbp)
    1975:	e9 db 00 00 00       	jmp    1a55 <main+0x7d5>
    197a:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    197e:	48 83 f8 00          	cmp    $0x0,%rax
    1982:	0f 84 c8 00 00 00    	je     1a50 <main+0x7d0>
    1988:	bf 01 00 00 00       	mov    $0x1,%edi
    198d:	be 20 00 00 00       	mov    $0x20,%esi
    1992:	e8 e9 f6 ff ff       	call   1080 <_sym_build_integer@plt>
    1997:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    199b:	48 89 c6             	mov    %rax,%rsi
    199e:	e8 fd f6 ff ff       	call   10a0 <_sym_build_not_equal@plt>
    19a3:	48 89 c7             	mov    %rax,%rdi
    19a6:	be 01 00 00 00       	mov    $0x1,%esi
    19ab:	48 ba f0 ac f5 c5 55 	movabs $0x5c55c5f5acf0,%rdx
    19b2:	5c 00 00 
    19b5:	e8 76 f7 ff ff       	call   1130 <_sym_push_path_constraint@plt>
    19ba:	bf 02 00 00 00       	mov    $0x2,%edi
    19bf:	be 20 00 00 00       	mov    $0x20,%esi
    19c4:	e8 b7 f6 ff ff       	call   1080 <_sym_build_integer@plt>
    19c9:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    19cd:	48 89 c6             	mov    %rax,%rsi
    19d0:	e8 cb f6 ff ff       	call   10a0 <_sym_build_not_equal@plt>
    19d5:	48 89 c7             	mov    %rax,%rdi
    19d8:	be 01 00 00 00       	mov    $0x1,%esi
    19dd:	48 ba f0 ac f5 c5 55 	movabs $0x5c55c5f5acf0,%rdx
    19e4:	5c 00 00 
    19e7:	e8 44 f7 ff ff       	call   1130 <_sym_push_path_constraint@plt>
    19ec:	bf 04 00 00 00       	mov    $0x4,%edi
    19f1:	be 20 00 00 00       	mov    $0x20,%esi
    19f6:	e8 85 f6 ff ff       	call   1080 <_sym_build_integer@plt>
    19fb:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    19ff:	48 89 c6             	mov    %rax,%rsi
    1a02:	e8 99 f6 ff ff       	call   10a0 <_sym_build_not_equal@plt>
    1a07:	48 89 c7             	mov    %rax,%rdi
    1a0a:	be 01 00 00 00       	mov    $0x1,%esi
    1a0f:	48 ba f0 ac f5 c5 55 	movabs $0x5c55c5f5acf0,%rdx
    1a16:	5c 00 00 
    1a19:	e8 12 f7 ff ff       	call   1130 <_sym_push_path_constraint@plt>
    1a1e:	bf 05 00 00 00       	mov    $0x5,%edi
    1a23:	be 20 00 00 00       	mov    $0x20,%esi
    1a28:	e8 53 f6 ff ff       	call   1080 <_sym_build_integer@plt>
    1a2d:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    1a31:	48 89 c6             	mov    %rax,%rsi
    1a34:	e8 67 f6 ff ff       	call   10a0 <_sym_build_not_equal@plt>
    1a39:	48 89 c7             	mov    %rax,%rdi
    1a3c:	be 01 00 00 00       	mov    $0x1,%esi
    1a41:	48 ba f0 ac f5 c5 55 	movabs $0x5c55c5f5acf0,%rdx
    1a48:	5c 00 00 
    1a4b:	e8 e0 f6 ff ff       	call   1130 <_sym_push_path_constraint@plt>
    1a50:	e9 00 00 00 00       	jmp    1a55 <main+0x7d5>
    1a55:	48 bf 20 6b f7 c5 55 	movabs $0x5c55c5f76b20,%rdi
    1a5c:	5c 00 00 
    1a5f:	e8 dc f6 ff ff       	call   1140 <_sym_notify_basic_block@plt>
    1a64:	48 8d 7d f4          	lea    -0xc(%rbp),%rdi
    1a68:	be 04 00 00 00       	mov    $0x4,%esi
    1a6d:	ba 01 00 00 00       	mov    $0x1,%edx
    1a72:	e8 a9 f6 ff ff       	call   1120 <_sym_read_memory@plt>
    1a77:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    1a7e:	8b 45 f4             	mov    -0xc(%rbp),%eax
    1a81:	89 85 ec fe ff ff    	mov    %eax,-0x114(%rbp)
    1a87:	48 8d 7d f0          	lea    -0x10(%rbp),%rdi
    1a8b:	be 04 00 00 00       	mov    $0x4,%esi
    1a90:	ba 01 00 00 00       	mov    $0x1,%edx
    1a95:	e8 86 f6 ff ff       	call   1120 <_sym_read_memory@plt>
    1a9a:	48 8b 8d f0 fe ff ff 	mov    -0x110(%rbp),%rcx
    1aa1:	48 89 c2             	mov    %rax,%rdx
    1aa4:	48 89 95 f8 fe ff ff 	mov    %rdx,-0x108(%rbp)
    1aab:	8b 45 f0             	mov    -0x10(%rbp),%eax
    1aae:	89 85 00 ff ff ff    	mov    %eax,-0x100(%rbp)
    1ab4:	31 c0                	xor    %eax,%eax
    1ab6:	48 39 c8             	cmp    %rcx,%rax
    1ab9:	0f 94 c1             	sete   %cl
    1abc:	88 8d 06 ff ff ff    	mov    %cl,-0xfa(%rbp)
    1ac2:	31 c0                	xor    %eax,%eax
    1ac4:	48 39 d0             	cmp    %rdx,%rax
    1ac7:	0f 94 c0             	sete   %al
    1aca:	88 85 07 ff ff ff    	mov    %al,-0xf9(%rbp)
    1ad0:	20 c1                	and    %al,%cl
    1ad2:	31 c0                	xor    %eax,%eax
    1ad4:	f6 c1 01             	test   $0x1,%cl
    1ad7:	48 89 85 08 ff ff ff 	mov    %rax,-0xf8(%rbp)
    1ade:	0f 85 a2 00 00 00    	jne    1b86 <main+0x906>
    1ae4:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
    1aeb:	8a 8d 06 ff ff ff    	mov    -0xfa(%rbp),%cl
    1af1:	f6 c1 01             	test   $0x1,%cl
    1af4:	48 89 85 e0 fe ff ff 	mov    %rax,-0x120(%rbp)
    1afb:	0f 85 05 00 00 00    	jne    1b06 <main+0x886>
    1b01:	e9 1b 00 00 00       	jmp    1b21 <main+0x8a1>
    1b06:	8b 85 ec fe ff ff    	mov    -0x114(%rbp),%eax
    1b0c:	89 c0                	mov    %eax,%eax
    1b0e:	89 c7                	mov    %eax,%edi
    1b10:	be 20 00 00 00       	mov    $0x20,%esi
    1b15:	e8 66 f5 ff ff       	call   1080 <_sym_build_integer@plt>
    1b1a:	48 89 85 e0 fe ff ff 	mov    %rax,-0x120(%rbp)
    1b21:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
    1b28:	8a 8d 07 ff ff ff    	mov    -0xf9(%rbp),%cl
    1b2e:	48 8b 95 e0 fe ff ff 	mov    -0x120(%rbp),%rdx
    1b35:	48 89 95 d0 fe ff ff 	mov    %rdx,-0x130(%rbp)
    1b3c:	f6 c1 01             	test   $0x1,%cl
    1b3f:	48 89 85 d8 fe ff ff 	mov    %rax,-0x128(%rbp)
    1b46:	0f 85 05 00 00 00    	jne    1b51 <main+0x8d1>
    1b4c:	e9 1b 00 00 00       	jmp    1b6c <main+0x8ec>
    1b51:	8b 85 00 ff ff ff    	mov    -0x100(%rbp),%eax
    1b57:	89 c0                	mov    %eax,%eax
    1b59:	89 c7                	mov    %eax,%edi
    1b5b:	be 20 00 00 00       	mov    $0x20,%esi
    1b60:	e8 1b f5 ff ff       	call   1080 <_sym_build_integer@plt>
    1b65:	48 89 85 d8 fe ff ff 	mov    %rax,-0x128(%rbp)
    1b6c:	48 8b bd d0 fe ff ff 	mov    -0x130(%rbp),%rdi
    1b73:	48 8b b5 d8 fe ff ff 	mov    -0x128(%rbp),%rsi
    1b7a:	e8 51 f5 ff ff       	call   10d0 <_sym_build_sub@plt>
    1b7f:	48 89 85 08 ff ff ff 	mov    %rax,-0xf8(%rbp)
    1b86:	8b 8d 00 ff ff ff    	mov    -0x100(%rbp),%ecx
    1b8c:	8b 85 ec fe ff ff    	mov    -0x114(%rbp),%eax
    1b92:	48 8b 95 08 ff ff ff 	mov    -0xf8(%rbp),%rdx
    1b99:	29 c8                	sub    %ecx,%eax
    1b9b:	89 85 cc fe ff ff    	mov    %eax,-0x134(%rbp)
    1ba1:	48 8d 7d ec          	lea    -0x14(%rbp),%rdi
    1ba5:	be 04 00 00 00       	mov    $0x4,%esi
    1baa:	b9 01 00 00 00       	mov    $0x1,%ecx
    1baf:	e8 bc f5 ff ff       	call   1170 <_sym_write_memory@plt>
    1bb4:	8b 85 cc fe ff ff    	mov    -0x134(%rbp),%eax
    1bba:	89 45 ec             	mov    %eax,-0x14(%rbp)
    1bbd:	e9 db 00 00 00       	jmp    1c9d <main+0xa1d>
    1bc2:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    1bc6:	48 83 f8 00          	cmp    $0x0,%rax
    1bca:	0f 84 c8 00 00 00    	je     1c98 <main+0xa18>
    1bd0:	bf 01 00 00 00       	mov    $0x1,%edi
    1bd5:	be 20 00 00 00       	mov    $0x20,%esi
    1bda:	e8 a1 f4 ff ff       	call   1080 <_sym_build_integer@plt>
    1bdf:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    1be3:	48 89 c6             	mov    %rax,%rsi
    1be6:	e8 b5 f4 ff ff       	call   10a0 <_sym_build_not_equal@plt>
    1beb:	48 89 c7             	mov    %rax,%rdi
    1bee:	be 01 00 00 00       	mov    $0x1,%esi
    1bf3:	48 ba b0 b9 f5 c5 55 	movabs $0x5c55c5f5b9b0,%rdx
    1bfa:	5c 00 00 
    1bfd:	e8 2e f5 ff ff       	call   1130 <_sym_push_path_constraint@plt>
    1c02:	bf 02 00 00 00       	mov    $0x2,%edi
    1c07:	be 20 00 00 00       	mov    $0x20,%esi
    1c0c:	e8 6f f4 ff ff       	call   1080 <_sym_build_integer@plt>
    1c11:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    1c15:	48 89 c6             	mov    %rax,%rsi
    1c18:	e8 83 f4 ff ff       	call   10a0 <_sym_build_not_equal@plt>
    1c1d:	48 89 c7             	mov    %rax,%rdi
    1c20:	be 01 00 00 00       	mov    $0x1,%esi
    1c25:	48 ba b0 b9 f5 c5 55 	movabs $0x5c55c5f5b9b0,%rdx
    1c2c:	5c 00 00 
    1c2f:	e8 fc f4 ff ff       	call   1130 <_sym_push_path_constraint@plt>
    1c34:	bf 03 00 00 00       	mov    $0x3,%edi
    1c39:	be 20 00 00 00       	mov    $0x20,%esi
    1c3e:	e8 3d f4 ff ff       	call   1080 <_sym_build_integer@plt>
    1c43:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    1c47:	48 89 c6             	mov    %rax,%rsi
    1c4a:	e8 51 f4 ff ff       	call   10a0 <_sym_build_not_equal@plt>
    1c4f:	48 89 c7             	mov    %rax,%rdi
    1c52:	be 01 00 00 00       	mov    $0x1,%esi
    1c57:	48 ba b0 b9 f5 c5 55 	movabs $0x5c55c5f5b9b0,%rdx
    1c5e:	5c 00 00 
    1c61:	e8 ca f4 ff ff       	call   1130 <_sym_push_path_constraint@plt>
    1c66:	bf 05 00 00 00       	mov    $0x5,%edi
    1c6b:	be 20 00 00 00       	mov    $0x20,%esi
    1c70:	e8 0b f4 ff ff       	call   1080 <_sym_build_integer@plt>
    1c75:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    1c79:	48 89 c6             	mov    %rax,%rsi
    1c7c:	e8 1f f4 ff ff       	call   10a0 <_sym_build_not_equal@plt>
    1c81:	48 89 c7             	mov    %rax,%rdi
    1c84:	be 01 00 00 00       	mov    $0x1,%esi
    1c89:	48 ba b0 b9 f5 c5 55 	movabs $0x5c55c5f5b9b0,%rdx
    1c90:	5c 00 00 
    1c93:	e8 98 f4 ff ff       	call   1130 <_sym_push_path_constraint@plt>
    1c98:	e9 00 00 00 00       	jmp    1c9d <main+0xa1d>
    1c9d:	48 bf 40 6e f7 c5 55 	movabs $0x5c55c5f76e40,%rdi
    1ca4:	5c 00 00 
    1ca7:	e8 94 f4 ff ff       	call   1140 <_sym_notify_basic_block@plt>
    1cac:	48 8d 7d f4          	lea    -0xc(%rbp),%rdi
    1cb0:	be 04 00 00 00       	mov    $0x4,%esi
    1cb5:	ba 01 00 00 00       	mov    $0x1,%edx
    1cba:	e8 61 f4 ff ff       	call   1120 <_sym_read_memory@plt>
    1cbf:	48 89 85 a8 fe ff ff 	mov    %rax,-0x158(%rbp)
    1cc6:	8b 45 f4             	mov    -0xc(%rbp),%eax
    1cc9:	89 85 a4 fe ff ff    	mov    %eax,-0x15c(%rbp)
    1ccf:	48 8d 7d f0          	lea    -0x10(%rbp),%rdi
    1cd3:	be 04 00 00 00       	mov    $0x4,%esi
    1cd8:	ba 01 00 00 00       	mov    $0x1,%edx
    1cdd:	e8 3e f4 ff ff       	call   1120 <_sym_read_memory@plt>
    1ce2:	48 8b 8d a8 fe ff ff 	mov    -0x158(%rbp),%rcx
    1ce9:	48 89 c2             	mov    %rax,%rdx
    1cec:	48 89 95 b0 fe ff ff 	mov    %rdx,-0x150(%rbp)
    1cf3:	8b 45 f0             	mov    -0x10(%rbp),%eax
    1cf6:	89 85 b8 fe ff ff    	mov    %eax,-0x148(%rbp)
    1cfc:	31 c0                	xor    %eax,%eax
    1cfe:	48 39 c8             	cmp    %rcx,%rax
    1d01:	0f 94 c1             	sete   %cl
    1d04:	88 8d be fe ff ff    	mov    %cl,-0x142(%rbp)
    1d0a:	31 c0                	xor    %eax,%eax
    1d0c:	48 39 d0             	cmp    %rdx,%rax
    1d0f:	0f 94 c0             	sete   %al
    1d12:	88 85 bf fe ff ff    	mov    %al,-0x141(%rbp)
    1d18:	20 c1                	and    %al,%cl
    1d1a:	31 c0                	xor    %eax,%eax
    1d1c:	f6 c1 01             	test   $0x1,%cl
    1d1f:	48 89 85 c0 fe ff ff 	mov    %rax,-0x140(%rbp)
    1d26:	0f 85 a2 00 00 00    	jne    1dce <main+0xb4e>
    1d2c:	48 8b 85 a8 fe ff ff 	mov    -0x158(%rbp),%rax
    1d33:	8a 8d be fe ff ff    	mov    -0x142(%rbp),%cl
    1d39:	f6 c1 01             	test   $0x1,%cl
    1d3c:	48 89 85 98 fe ff ff 	mov    %rax,-0x168(%rbp)
    1d43:	0f 85 05 00 00 00    	jne    1d4e <main+0xace>
    1d49:	e9 1b 00 00 00       	jmp    1d69 <main+0xae9>
    1d4e:	8b 85 a4 fe ff ff    	mov    -0x15c(%rbp),%eax
    1d54:	89 c0                	mov    %eax,%eax
    1d56:	89 c7                	mov    %eax,%edi
    1d58:	be 20 00 00 00       	mov    $0x20,%esi
    1d5d:	e8 1e f3 ff ff       	call   1080 <_sym_build_integer@plt>
    1d62:	48 89 85 98 fe ff ff 	mov    %rax,-0x168(%rbp)
    1d69:	48 8b 85 b0 fe ff ff 	mov    -0x150(%rbp),%rax
    1d70:	8a 8d bf fe ff ff    	mov    -0x141(%rbp),%cl
    1d76:	48 8b 95 98 fe ff ff 	mov    -0x168(%rbp),%rdx
    1d7d:	48 89 95 88 fe ff ff 	mov    %rdx,-0x178(%rbp)
    1d84:	f6 c1 01             	test   $0x1,%cl
    1d87:	48 89 85 90 fe ff ff 	mov    %rax,-0x170(%rbp)
    1d8e:	0f 85 05 00 00 00    	jne    1d99 <main+0xb19>
    1d94:	e9 1b 00 00 00       	jmp    1db4 <main+0xb34>
    1d99:	8b 85 b8 fe ff ff    	mov    -0x148(%rbp),%eax
    1d9f:	89 c0                	mov    %eax,%eax
    1da1:	89 c7                	mov    %eax,%edi
    1da3:	be 20 00 00 00       	mov    $0x20,%esi
    1da8:	e8 d3 f2 ff ff       	call   1080 <_sym_build_integer@plt>
    1dad:	48 89 85 90 fe ff ff 	mov    %rax,-0x170(%rbp)
    1db4:	48 8b bd 88 fe ff ff 	mov    -0x178(%rbp),%rdi
    1dbb:	48 8b b5 90 fe ff ff 	mov    -0x170(%rbp),%rsi
    1dc2:	e8 39 f3 ff ff       	call   1100 <_sym_build_signed_div@plt>
    1dc7:	48 89 85 c0 fe ff ff 	mov    %rax,-0x140(%rbp)
    1dce:	8b 8d b8 fe ff ff    	mov    -0x148(%rbp),%ecx
    1dd4:	8b 85 a4 fe ff ff    	mov    -0x15c(%rbp),%eax
    1dda:	48 8b 95 c0 fe ff ff 	mov    -0x140(%rbp),%rdx
    1de1:	48 89 95 78 fe ff ff 	mov    %rdx,-0x188(%rbp)
    1de8:	99                   	cltd
    1de9:	f7 f9                	idiv   %ecx
    1deb:	48 8b 95 78 fe ff ff 	mov    -0x188(%rbp),%rdx
    1df2:	89 85 84 fe ff ff    	mov    %eax,-0x17c(%rbp)
    1df8:	48 8d 7d ec          	lea    -0x14(%rbp),%rdi
    1dfc:	be 04 00 00 00       	mov    $0x4,%esi
    1e01:	b9 01 00 00 00       	mov    $0x1,%ecx
    1e06:	e8 65 f3 ff ff       	call   1170 <_sym_write_memory@plt>
    1e0b:	8b 85 84 fe ff ff    	mov    -0x17c(%rbp),%eax
    1e11:	89 45 ec             	mov    %eax,-0x14(%rbp)
    1e14:	e9 db 00 00 00       	jmp    1ef4 <main+0xc74>
    1e19:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
    1e1d:	48 83 f8 00          	cmp    $0x0,%rax
    1e21:	0f 84 c8 00 00 00    	je     1eef <main+0xc6f>
    1e27:	bf 01 00 00 00       	mov    $0x1,%edi
    1e2c:	be 20 00 00 00       	mov    $0x20,%esi
    1e31:	e8 4a f2 ff ff       	call   1080 <_sym_build_integer@plt>
    1e36:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    1e3a:	48 89 c6             	mov    %rax,%rsi
    1e3d:	e8 5e f2 ff ff       	call   10a0 <_sym_build_not_equal@plt>
    1e42:	48 89 c7             	mov    %rax,%rdi
    1e45:	be 01 00 00 00       	mov    $0x1,%esi
    1e4a:	48 ba 70 c6 f5 c5 55 	movabs $0x5c55c5f5c670,%rdx
    1e51:	5c 00 00 
    1e54:	e8 d7 f2 ff ff       	call   1130 <_sym_push_path_constraint@plt>
    1e59:	bf 02 00 00 00       	mov    $0x2,%edi
    1e5e:	be 20 00 00 00       	mov    $0x20,%esi
    1e63:	e8 18 f2 ff ff       	call   1080 <_sym_build_integer@plt>
    1e68:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    1e6c:	48 89 c6             	mov    %rax,%rsi
    1e6f:	e8 2c f2 ff ff       	call   10a0 <_sym_build_not_equal@plt>
    1e74:	48 89 c7             	mov    %rax,%rdi
    1e77:	be 01 00 00 00       	mov    $0x1,%esi
    1e7c:	48 ba 70 c6 f5 c5 55 	movabs $0x5c55c5f5c670,%rdx
    1e83:	5c 00 00 
    1e86:	e8 a5 f2 ff ff       	call   1130 <_sym_push_path_constraint@plt>
    1e8b:	bf 03 00 00 00       	mov    $0x3,%edi
    1e90:	be 20 00 00 00       	mov    $0x20,%esi
    1e95:	e8 e6 f1 ff ff       	call   1080 <_sym_build_integer@plt>
    1e9a:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    1e9e:	48 89 c6             	mov    %rax,%rsi
    1ea1:	e8 fa f1 ff ff       	call   10a0 <_sym_build_not_equal@plt>
    1ea6:	48 89 c7             	mov    %rax,%rdi
    1ea9:	be 01 00 00 00       	mov    $0x1,%esi
    1eae:	48 ba 70 c6 f5 c5 55 	movabs $0x5c55c5f5c670,%rdx
    1eb5:	5c 00 00 
    1eb8:	e8 73 f2 ff ff       	call   1130 <_sym_push_path_constraint@plt>
    1ebd:	bf 04 00 00 00       	mov    $0x4,%edi
    1ec2:	be 20 00 00 00       	mov    $0x20,%esi
    1ec7:	e8 b4 f1 ff ff       	call   1080 <_sym_build_integer@plt>
    1ecc:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    1ed0:	48 89 c6             	mov    %rax,%rsi
    1ed3:	e8 c8 f1 ff ff       	call   10a0 <_sym_build_not_equal@plt>
    1ed8:	48 89 c7             	mov    %rax,%rdi
    1edb:	be 01 00 00 00       	mov    $0x1,%esi
    1ee0:	48 ba 70 c6 f5 c5 55 	movabs $0x5c55c5f5c670,%rdx
    1ee7:	5c 00 00 
    1eea:	e8 41 f2 ff ff       	call   1130 <_sym_push_path_constraint@plt>
    1eef:	e9 00 00 00 00       	jmp    1ef4 <main+0xc74>
    1ef4:	48 bf 60 71 f7 c5 55 	movabs $0x5c55c5f77160,%rdi
    1efb:	5c 00 00 
    1efe:	e8 3d f2 ff ff       	call   1140 <_sym_notify_basic_block@plt>
    1f03:	e9 e4 00 00 00       	jmp    1fec <main+0xd6c>
    1f08:	48 bf 70 62 f7 c5 55 	movabs $0x5c55c5f76270,%rdi
    1f0f:	5c 00 00 
    1f12:	e8 29 f2 ff ff       	call   1140 <_sym_notify_basic_block@plt>
    1f17:	48 8d 7d ec          	lea    -0x14(%rbp),%rdi
    1f1b:	be 04 00 00 00       	mov    $0x4,%esi
    1f20:	31 c0                	xor    %eax,%eax
    1f22:	89 c2                	mov    %eax,%edx
    1f24:	b9 01 00 00 00       	mov    $0x1,%ecx
    1f29:	e8 42 f2 ff ff       	call   1170 <_sym_write_memory@plt>
    1f2e:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%rbp)
    1f35:	48 8b 3d 94 30 00 00 	mov    0x3094(%rip),%rdi        # 4fd0 <stderr@GLIBC_2.2.5>
    1f3c:	be 08 00 00 00       	mov    $0x8,%esi
    1f41:	ba 01 00 00 00       	mov    $0x1,%edx
    1f46:	e8 d5 f1 ff ff       	call   1120 <_sym_read_memory@plt>
    1f4b:	48 89 85 58 fe ff ff 	mov    %rax,-0x1a8(%rbp)
    1f52:	48 8b 05 77 30 00 00 	mov    0x3077(%rip),%rax        # 4fd0 <stderr@GLIBC_2.2.5>
    1f59:	48 8b 00             	mov    (%rax),%rax
    1f5c:	48 89 85 68 fe ff ff 	mov    %rax,-0x198(%rbp)
    1f63:	48 8d 7d f8          	lea    -0x8(%rbp),%rdi
    1f67:	be 04 00 00 00       	mov    $0x4,%esi
    1f6c:	ba 01 00 00 00       	mov    $0x1,%edx
    1f71:	e8 aa f1 ff ff       	call   1120 <_sym_read_memory@plt>
    1f76:	48 89 85 60 fe ff ff 	mov    %rax,-0x1a0(%rbp)
    1f7d:	8b 45 f8             	mov    -0x8(%rbp),%eax
    1f80:	89 85 74 fe ff ff    	mov    %eax,-0x18c(%rbp)
    1f86:	48 bf b0 b7 e1 c5 55 	movabs $0x5c55c5e1b7b0,%rdi
    1f8d:	5c 00 00 
    1f90:	e8 cb f1 ff ff       	call   1160 <_sym_notify_call@plt>
    1f95:	48 8b b5 58 fe ff ff 	mov    -0x1a8(%rbp),%rsi
    1f9c:	31 ff                	xor    %edi,%edi
    1f9e:	e8 ad f1 ff ff       	call   1150 <_sym_set_parameter_expression@plt>
    1fa3:	bf 01 00 00 00       	mov    $0x1,%edi
    1fa8:	31 c0                	xor    %eax,%eax
    1faa:	89 c6                	mov    %eax,%esi
    1fac:	e8 9f f1 ff ff       	call   1150 <_sym_set_parameter_expression@plt>
    1fb1:	48 8b b5 60 fe ff ff 	mov    -0x1a0(%rbp),%rsi
    1fb8:	bf 02 00 00 00       	mov    $0x2,%edi
    1fbd:	e8 8e f1 ff ff       	call   1150 <_sym_set_parameter_expression@plt>
    1fc2:	48 8b bd 68 fe ff ff 	mov    -0x198(%rbp),%rdi
    1fc9:	8b 95 74 fe ff ff    	mov    -0x18c(%rbp),%edx
    1fcf:	48 8d 35 5b 10 00 00 	lea    0x105b(%rip),%rsi        # 3031 <_IO_stdin_used+0x31>
    1fd6:	b0 00                	mov    $0x0,%al
    1fd8:	e8 63 f0 ff ff       	call   1040 <fprintf@plt>
    1fdd:	48 bf b0 b7 e1 c5 55 	movabs $0x5c55c5e1b7b0,%rdi
    1fe4:	5c 00 00 
    1fe7:	e8 c4 f0 ff ff       	call   10b0 <_sym_notify_ret@plt>
    1fec:	48 bf a0 61 f7 c5 55 	movabs $0x5c55c5f761a0,%rdi
    1ff3:	5c 00 00 
    1ff6:	e8 45 f1 ff ff       	call   1140 <_sym_notify_basic_block@plt>
    1ffb:	48 8d 7d ec          	lea    -0x14(%rbp),%rdi
    1fff:	be 04 00 00 00       	mov    $0x4,%esi
    2004:	ba 01 00 00 00       	mov    $0x1,%edx
    2009:	e8 12 f1 ff ff       	call   1120 <_sym_read_memory@plt>
    200e:	48 89 85 48 fe ff ff 	mov    %rax,-0x1b8(%rbp)
    2015:	8b 45 ec             	mov    -0x14(%rbp),%eax
    2018:	89 85 54 fe ff ff    	mov    %eax,-0x1ac(%rbp)
    201e:	48 bf 00 79 f7 c5 55 	movabs $0x5c55c5f77900,%rdi
    2025:	5c 00 00 
    2028:	e8 33 f1 ff ff       	call   1160 <_sym_notify_call@plt>
    202d:	31 ff                	xor    %edi,%edi
    202f:	31 c0                	xor    %eax,%eax
    2031:	89 c6                	mov    %eax,%esi
    2033:	e8 18 f1 ff ff       	call   1150 <_sym_set_parameter_expression@plt>
    2038:	48 8b b5 48 fe ff ff 	mov    -0x1b8(%rbp),%rsi
    203f:	bf 01 00 00 00       	mov    $0x1,%edi
    2044:	e8 07 f1 ff ff       	call   1150 <_sym_set_parameter_expression@plt>
    2049:	8b b5 54 fe ff ff    	mov    -0x1ac(%rbp),%esi
    204f:	48 8d 3d f0 0f 00 00 	lea    0xff0(%rip),%rdi        # 3046 <_IO_stdin_used+0x46>
    2056:	b0 00                	mov    $0x0,%al
    2058:	e8 d3 ef ff ff       	call   1030 <printf@plt>
    205d:	48 bf 00 79 f7 c5 55 	movabs $0x5c55c5f77900,%rdi
    2064:	5c 00 00 
    2067:	e8 44 f0 ff ff       	call   10b0 <_sym_notify_ret@plt>
    206c:	31 c0                	xor    %eax,%eax
    206e:	89 c7                	mov    %eax,%edi
    2070:	e8 db ef ff ff       	call   1050 <_sym_set_return_expression@plt>
    2075:	31 c0                	xor    %eax,%eax
    2077:	48 81 c4 c0 01 00 00 	add    $0x1c0,%rsp
    207e:	5d                   	pop    %rbp
    207f:	c3                   	ret

0000000000002080 <__sym_ctor>:
    2080:	55                   	push   %rbp
    2081:	48 89 e5             	mov    %rsp,%rbp
    2084:	e8 87 f0 ff ff       	call   1110 <_sym_initialize@plt>
    2089:	5d                   	pop    %rbp
    208a:	c3                   	ret

Disassembly of section .fini:

000000000000208c <_fini>:
    208c:	f3 0f 1e fa          	endbr64
    2090:	48 83 ec 08          	sub    $0x8,%rsp
    2094:	48 83 c4 08          	add    $0x8,%rsp
    2098:	c3                   	ret
