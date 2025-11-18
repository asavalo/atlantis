import java
import safe_callable

from SafeCallable c, Annotation ann, AnnotationType anntp
where
    ann = c.getAnAnnotation() and
    anntp = ann.getType() and
    anntp.hasQualifiedName("com.code_intelligence.jazzer.junit", "FuzzTest")
select
  c as func,
  c.getSafeAbsolutePath() as file_abs,
  c.getSafeDeclaringTypeSimpleName() as class_name,
  anntp.getName() as ann_name,
  anntp.getQualifiedName() as ann_qualified_name