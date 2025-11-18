from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.mock import MockEvaluator
from crete.framework.tools.services import SearchSymbolTool


@pytest.mark.slow
def test_regress_search_symbol_1(
    detection_c_r2_sqlite3_cpv_1: tuple[Path, Path],
):
    context, _detection = AIxCCContextBuilder(
        *detection_c_r2_sqlite3_cpv_1,
        evaluator=MockEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    symbol_name = "shell_error_context"
    ret = SearchSymbolTool(
        context, context["pool"].source_directory, with_line_number=True
    )._run(symbol_name)  # pyright: ignore[reportPrivateUsage]

    assert (
        ret
        == r"""  3089: static char *shell_error_context(const char *zSql, sqlite3 *db){
  3090:   int iOffset;
  3091:   size_t len;
  3092:   char *zCode;
  3093:   char *zMsg;
  3094:   int i;
  3095:   if( db==0
  3096:    || zSql==0
  3097:    || (iOffset = sqlite3_error_offset(db))<0
  3098:   ){
  3099:     return sqlite3_mprintf("");
  3100:   }
  3101:   while( iOffset>50 ){
  3102:     iOffset--;
  3103:     zSql++;
  3104:     while( (zSql[0]&0xc0)==0x80 ){ zSql++; iOffset--; }
  3105:   }
  3106:   len = strlen(zSql);
  3107:   if( len>78 ){
  3108:     len = 78;
  3109:     while( len>0 && (zSql[len]&0xc0)==0x80 ) len--;
  3110:   }
  3111:   zCode = sqlite3_mprintf("%.*s", len, zSql);
  3112:   shell_check_oom(zCode);
  3113:   for(i=0; zCode[i]; i++){ if( IsSpace(zSql[i]) ) zCode[i] = ' '; }
  3114:   if( iOffset<25 ){
  3115:     zMsg = sqlite3_mprintf("\n  %z\n  %*s^--- error here", zCode,iOffset,"");
  3116:   }else{
  3117:     zMsg = sqlite3_mprintf("\n  %z\n  %*serror here ---^", zCode,iOffset-14,"");
  3118:   }
  3119:   return zMsg;
  3120: }"""
    )


@pytest.mark.regression("Issue#874")
@pytest.mark.slow
def test_regress_search_symbol_874(
    detection_c_asc_nginx_cpv_10: tuple[Path, Path],
):
    context, _detection = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_10,
        evaluator=MockEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    symbol_name = "ngx_http_parse_multi_header_lines"
    ret = SearchSymbolTool(
        context, context["pool"].source_directory, with_line_number=True
    )._run(symbol_name)  # pyright: ignore[reportPrivateUsage]

    assert (
        ret
        == r"""  1963: ngx_table_elt_t *
  1964: ngx_http_parse_multi_header_lines(ngx_http_request_t *r,
  1965:     ngx_table_elt_t *headers, ngx_str_t *name, ngx_str_t *value)
  1966: {
  1967:     u_char           *start, *last, *end, ch;
  1968:     ngx_table_elt_t  *h;
  1969: 
  1970:     for (h = headers; h; h = h->next) {
  1971: 
  1972:         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
  1973:                        "parse header: \"%V: %V\"", &h->key, &h->value);
  1974: 
  1975:         if (name->len > h->value.len) {
  1976:             continue;
  1977:         }
  1978: 
  1979:         start = h->value.data;
  1980:         end = h->value.data + h->value.len;
  1981: 
  1982:         while (start < end) {
  1983: 
  1984:             if (ngx_strncasecmp(start, name->data, name->len) != 0) {
  1985:                 goto skip;
  1986:             }
  1987: 
  1988:             for (start += name->len; start < end && *start == ' '; start++) {
  1989:                 /* void */
  1990:             }
  1991: 
  1992:             if (value == NULL) {
  1993:                 if (start == end || *start == ',') {
  1994:                     return h;
  1995:                 }
  1996: 
  1997:                 goto skip;
  1998:             }
  1999: 
  2000:             if (start == end || *start++ != '=') {
  2001:                 /* the invalid header value */
  2002:                 goto skip;
  2003:             }
  2004: 
  2005:             while (start < end && *start == ' ') { start++; }
  2006: 
  2007:             for (last = start; last < end && *last != ';'; last++) {
  2008:                 /* void */
  2009:             }
  2010: 
  2011:             value->len = last - start;
  2012:             value->data = start;
  2013: 
  2014:             return h;
  2015: 
  2016:         skip:
  2017: 
  2018:             while (start < end) {
  2019:                 ch = *start++;
  2020:                 if (ch == ';' || ch == ',') {
  2021:                     break;
  2022:                 }
  2023:             }
  2024: 
  2025:             while (start < end && *start == ' ') { start++; }
  2026:         }
  2027:     }
  2028: 
  2029:     return NULL;
  2030: }"""
    )


@pytest.mark.regression("Issue#1367")
@pytest.mark.slow
def test_regress_search_symbol_1367(
    detection_jvm_r3_apache_commons_compress_delta_02_cpv_0: tuple[Path, Path],
):
    context, _detection = AIxCCContextBuilder(
        *detection_jvm_r3_apache_commons_compress_delta_02_cpv_0,
        evaluator=MockEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    symbol_name = "ZCompressorInputStream"
    file_or_directory_path = "src"

    ret = SearchSymbolTool(
        context,
        context["pool"].source_directory,
        with_line_number=True,
    )._run(symbol_name, file_or_directory_path)  # pyright: ignore[reportPrivateUsage]

    assert ret != "Error occurred while searching for the symbol. Try with other input."
    assert "33: public class ZCompressorInputStream extends LZWInputStream {" in ret


@pytest.mark.regression("Issue#1369")
@pytest.mark.slow
def test_regress_search_symbol_1369(
    detection_jvm_r3_apache_commons_compress_delta_02_cpv_0: tuple[Path, Path],
):
    context, _detection = AIxCCContextBuilder(
        *detection_jvm_r3_apache_commons_compress_delta_02_cpv_0,
        evaluator=MockEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    symbol_name = "class ZCompressorInputStream"
    file_or_directory_path = "src"

    ret = SearchSymbolTool(
        context,
        context["pool"].source_directory,
        with_line_number=True,
    )._run(symbol_name, file_or_directory_path)  # pyright: ignore[reportPrivateUsage]

    assert ret != "Error occurred while searching for the symbol. Try with other input."
    assert "33: public class ZCompressorInputStream extends LZWInputStream {" in ret
