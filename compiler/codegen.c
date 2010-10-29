/*
  Copyright (c) 2009 Robert G. Jakabosky
  
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:
  
  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.
  
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.

  MIT License: http://www.opensource.org/licenses/mit-license.php
*/

#include "codegen.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

/**
 *
 * CVariable
 *
 */
CVariable *new_CVariable(const char *type, const char *name) {
	CVariable *var = (CVariable *)malloc(sizeof(CVariable));
	var->type = strdup(type);
	var->name = strdup(name);
	var->refcount = 1;
	return var;
}

void free_CVariable_internal(CVariable *var) {
	free(var->type);
	free(var->name);
	free(var);
}

void CVariable_ref(CVariable *var) {
	var->refcount++;
}

void CVariable_unref(CVariable *var) {
	var->refcount--;
	if(var->refcount == 0) {
		free_CVariable_internal(var);
	}
}

/**
 *
 * CValue
 *
 */
static void clear_CValue(CValue *val) {
	switch(val->type) {
	case VOID:
	case INTEGER:
	case BOOLEAN:
	case DOUBLE:
		break;
	case STRING:
	case BINARY:
		free(val->data.str);
		val->data.str = NULL;
		break;
	case CODE:
		free(val->data.str);
		val->data.str = NULL;
		break;
	case VARIABLE:
		CVariable_unref(val->data.var);
		val->data.var = NULL;
		break;
	}
	val->len = 0;
	val->type = VOID;
}

void CValue_void(CValue *val) {
	clear_CValue(val);
}

void CValue_boolean(CValue *val, int is_true) {
	clear_CValue(val);
	val->type = BOOLEAN;
	val->len = 0;
	val->data.num = (is_true != 0) ? 1 : 0;
}

void CValue_integer(CValue *val, uint64_t num) {
	clear_CValue(val);
	val->type = INTEGER;
	val->len = 0;
	val->data.num = num;
}

void CValue_double(CValue *val, double dnum) {
	clear_CValue(val);
	val->type = DOUBLE;
	val->len = 0;
	val->data.dnum = dnum;
}

void CValue_code(CValue *val, const char *code) {
	clear_CValue(val);
	val->type = CODE;
	val->len = strlen(code);
	val->data.str = strdup(code);
}

void CValue_binary(CValue *val, const uint8_t *bin, uint32_t len) {
	uint8_t *tmp;
	clear_CValue(val);
	val->type = BINARY;
	val->len = len;
	tmp = (uint8_t *)malloc(len);
	memcpy(tmp, bin, len);
	val->data.bin = tmp;
}

void CValue_string_len(CValue *val, const char *str, uint32_t len) {
	CValue_binary(val, (const uint8_t *)str, len);
	val->type = STRING;
}

void CValue_variable(CValue *val, const char *type, const char *name) {
	clear_CValue(val);
	val->type = VARIABLE;
	val->data.var = new_CVariable(type, name);
}

void CValue_set(CValue *val, const CValue *new_val) {
	clear_CValue(val);
	val->type = new_val->type;
	val->len = new_val->len;
	switch(val->type) {
	case VOID:
	case INTEGER:
	case BOOLEAN:
	case DOUBLE:
		val->data = new_val->data;
		break;
	case STRING:
		CValue_string_len(val, new_val->data.str, new_val->len);
		break;
	case BINARY:
		CValue_binary(val, new_val->data.bin, new_val->len);
		break;
	case CODE:
		val->data.str = strdup(new_val->data.str);
		break;
	case VARIABLE:
		CVariable_ref(new_val->data.var);
		val->data.var = new_val->data.var;
		break;
	}
}

/**
 *
 * CValues
 *
 */
static void grow_CValues(CValues *values, int need) {
	int new_size = values->len + need;
	int i;
	if(new_size < values->size) return;
	values->values = (CValue *)realloc(values->values, new_size * sizeof(CValue));
	/* clear new values. */
	for(i = values->size; i < new_size; i++) {
		values->values[i].type = VOID;
		values->values[i].data.num = 0;
	}
	values->size = new_size;
}

CValues *new_CValues(int len) {
	CValues *values = (CValues *)malloc(sizeof(CValues));
	values->len = len;
	values->size = 0;
	values->values = NULL;
	grow_CValues(values, 0);
	return values;
}

void clear_CValues(CValues *values) {
	int i;
	for(i = values->size - 1; i >= 0; i--) {
		CValue_void(&(values->values[i]));
	}
	values->len = 0;
}

void free_CValues(CValues *values) {
	clear_CValues(values);
	free(values->values);
	free(values);
}

void CValues_set(CValues *values, int idx, const CValue *val) {
	assert(idx >= 0 && idx < values->len);
	CValue_set(&(values->values[idx]), val);
}

const CValue *CValues_get(CValues *values, int idx) {
	assert(idx >= 0 && idx < values->len);
	if(values->values[idx].type == VOID) return NULL;
	return &(values->values[idx]);
}

void CValues_push_back(CValues *values, const CValue *val) {
	int idx = values->len;
	grow_CValues(values, 1);
	CValue_set(&(values->values[idx]), val);
	values->len += 1;
}

const CValue *CValues_pop_back(CValues *values) {
	int idx;
	values->len -= 1;
	idx = values->len;
	return &(values->values[idx]);
}

/**
 *
 * CFuncProto
 *
 */
CFuncProto *new_CFuncProto(const char *ret_type, const char *name, bool is_extern) {
	CFuncProto *proto = (CFuncProto *)malloc(sizeof(CFuncProto));
	proto->ret_type = strdup(ret_type);
	proto->name = strdup(name);
	proto->params = new_CValues(0);
	proto->is_extern = is_extern;
	return proto;
}

void free_CFuncProto(CFuncProto *proto) {
	free(proto->ret_type);
	free(proto->name);
	free_CValues(proto->params);
	free(proto);
}

void CFuncProto_create_param(CFuncProto *proto, CValue *val,
	const char *type, const char *name)
{
	char var_name[8192];
#if USE_PARAM_PREFIX
	snprintf(var_name, 8192, "param_%s", name);
#else
	snprintf(var_name, 8192, "%s", name);
#endif
	CValue_variable(val, type, var_name);
	CValues_push_back(proto->params, val);
}

CFuncProto *build_CFuncProto(const char *ret_type, const char *name, bool is_extern, ...) {
	CFuncProto *proto = new_CFuncProto(ret_type, name, is_extern);
	CValue val = { .type = VOID };
	va_list ap;
	char *param_type = NULL;
	char *param;

	va_start(ap, is_extern);
	while((param = va_arg(ap, char *)) != NULL) {
		if(param_type == NULL) {
			param_type = param;
			continue;
		}
		CFuncProto_create_param(proto, &val, param_type, param);
		param_type = NULL;
	}
	va_end(ap);
	CValue_void(&val);
	return proto;
}

int CFuncProto_dump(CFuncProto *proto, FILE *file, bool define) {
	const CVariable *var;
	const CValue *val;
	int len;
	int rc = 0;
	int total = 0;
	int i;
	/* gen function prototype. */
	if(proto->is_extern) {
		if(define) {
			rc = fprintf(file, "extern ");
			if(rc < 0) return -1;
			total += rc;
		}
	} else {
		rc = fprintf(file, "static ");
		if(rc < 0) return -1;
		total += rc;
	}
	rc = fprintf(file, "%s %s(", proto->ret_type, proto->name);
	if(rc < 0) return -1;
	total += rc;
	/* gen function parameters. */
	len = proto->params->len;
	for(i = 0; i < len;) {
		val = CValues_get(proto->params, i);
		assert(val->type == VARIABLE);
		var = val->data.var;
		rc = fprintf(file, "%s %s", var->type, var->name);
		if(rc < 0) return -1;
		total += rc;
		if((++i) < len) {
			rc = fprintf(file, ", ");
			if(rc < 0) return -1;
			total += rc;
		}
	}
	if(define) {
		rc = fprintf(file, ");\n");
	} else {
		rc = fprintf(file, ")");
	}
	if(rc < 0) return -1;
	total += rc;
	return total;
}

/**
 *
 * CodeBlock
 *
 */

#define GROW_SIZE 512
#define MIN_SIZE 128
#define CODE_WIDTH 80
static void grow_CodeBlock(CodeBlock *block, int need) {
	int new_size = block->len + need + GROW_SIZE;
	if(new_size < block->size) return;
	block->code = (char *)realloc(block->code, new_size);
	block->size = new_size;
}

CodeBlock *new_CodeBlock(CScope *scope, const char *name, int write_label) {
	CodeBlock *block = (CodeBlock *)malloc(sizeof(CodeBlock));
	block->scope = scope;
	block->next = NULL;
	block->name = strdup(name);
	block->code = NULL;
	block->len = 0;
	block->size = 0;
	grow_CodeBlock(block, 0);
	/* write goto label for code block. */
	if(write_label && CScope_is_func(scope)) {
		CodeBlock_printf(block, "block_%s:\n", name);
	}
	return block;
}

void free_CodeBlock(CodeBlock *block) {
	if(block == NULL) return;
	if(block->next) free_CodeBlock(block->next);
	free(block->name);
	free(block->code);
	free(block);
}

int CodeBlock_dump(CodeBlock *block, FILE *file) {
	size_t len;
	len = fwrite(block->code, 1, block->len, file);
	if(len < (size_t)block->len) return -len;
	return len;
}

int CodeBlock_print_binary_data(CodeBlock *block, const uint8_t *bin, int len) {
	int i;
	int rc;
	int wlen = 0;
	int width = 0;

#define BIN_CHAR_SIZE 5
#define BIN_CHAR_WIDTH (CODE_WIDTH / BIN_CHAR_SIZE)
	/* estimate total length. */
	wlen = 2; /* prefix. */
	wlen += (len * BIN_CHAR_SIZE); /* '0xXX,' values. */
	wlen += ((len + BIN_CHAR_WIDTH) / BIN_CHAR_WIDTH); /* newlines. */
	wlen += 3; /* postfix. */
	grow_CodeBlock(block, wlen);
	/* reset write len. */
	wlen = 0;
	rc = CodeBlock_printf(block, "{\n");
	if(rc <= 0) return rc;
	wlen += rc;
	for(i = 0; i < len; i++) {
		rc = CodeBlock_printf(block, "0x%.2x,", bin[i]);
		if(rc <= 0) return rc;
		width += rc;
		wlen += rc;
		if(width >= CODE_WIDTH) {
			rc = CodeBlock_printf(block, "\n");
			if(rc <= 0) return rc;
			width = 0;
			wlen += rc;
		}
	}
	if(width > 0) {
		rc = CodeBlock_printf(block, "\n");
		if(rc <= 0) return rc;
		wlen += rc;
	}
	rc = CodeBlock_printf(block, "};\n");
	if(rc <= 0) return rc;
	wlen += rc;
	return wlen;
}

static const unsigned char list_safe_punct[] = "~`!@#$%^&*()_+-=';:,./<>?[]{}|";
static const unsigned char list_escape_chars[] = "\n\t\v\b\r\f\a\"\\";
typedef enum {
	CharEncodeAsIs   = 0,
	CharEncodeEscape = 1,
	CharEncodeOct    = 2,
} CharEncodeType;
static int char_encode_init = 1;
static uint8_t char_encode[256];
#define ASIS_ENCODE_LEN 1 /* strlen("\n") */
#define ESCAPE_ENCODE_LEN 2 /* strlen("\\n") */
#define OCT_ENCODE_LEN 4 /* strlen("\\012") */
static void initialize_char_encode() {
	uint_fast32_t i;
	uint8_t ch;
	/* clear, mark all chars as needing octal-encoding. */
	for(i = 0; i < sizeof(char_encode); i++) char_encode[i] = CharEncodeOct;
	/* mark safe punct 'encode as-is' */
	for(i = 0; list_safe_punct[i] != 0; i++) {
		ch = list_safe_punct[i];
		char_encode[ch] = CharEncodeAsIs;
	}
	/* mark alphanum 'encode as-is' */
	for(ch = 'a'; ch <= 'z'; ch++) char_encode[ch] = CharEncodeAsIs;
	for(ch = 'A'; ch <= 'Z'; ch++) char_encode[ch] = CharEncodeAsIs;
	for(ch = '0'; ch <= '9'; ch++) char_encode[ch] = CharEncodeAsIs;
	/* space. */
	ch = ' ';
	char_encode[ch] = CharEncodeAsIs;
	/* clear, mark all chars as needing octal-encoding. */
	for(i = 0; list_escape_chars[i] != 0; i++) {
		ch = list_escape_chars[i];
		char_encode[ch] = CharEncodeEscape;
	}
	char_encode_init = 0;
}

int CodeBlock_print_quoted_str(CodeBlock *block, const char *str, int len) {
	char *out;
	uint_fast32_t needed;
	uint_fast32_t out_len;
	uint_fast32_t out_old_len;
	uint_fast32_t out_size;
	uint_fast32_t str_len;
	uint_fast32_t str_off;
	char ch;
	CharEncodeType encode;
	int rc;

	if(char_encode_init) {
		initialize_char_encode();
	}

	rc = CodeBlock_printf(block, "\"");
	if(rc < 0) return rc;

	str_len = len;
	str_off = 0;
	needed = (MIN_SIZE > str_len) ? MIN_SIZE : str_len;

	out_len = block->len;
	out_old_len = out_len;
	out_size = block->size;

	do {
		/* make room for quoted string. */
		if((out_size - out_len) < needed) {
			grow_CodeBlock(block, needed);
			out_size = block->size;
		}
		out = block->code;
		/* leave room for a full '\377' encoded char. */
		out_size -= OCT_ENCODE_LEN+1;
		while(out_len <= out_size) {
			if(str_off >= str_len) goto done;
			ch = str[str_off++];
			/* get char encode type. */
			encode = char_encode[(uint8_t)ch];
			switch(encode) {
			case CharEncodeAsIs:
				out[out_len++] = ch;
				break;
			case CharEncodeEscape:
				out[out_len++] = '\\';
				switch(ch) {
				case '\n': ch = 'n'; break;
				case '\t': ch = 't'; break;
				case '\v': ch = 'v'; break;
				case '\b': ch = 'b'; break;
				case '\r': ch = 'r'; break;
				case '\f': ch = 'f'; break;
				case '\a': ch = 'a'; break;
				case '\"':
				case '\\':
					break;
				default:
					fprintf(stderr, "Can't escape character(0x%x) = %c.\n", (uint8_t)ch, ch);
					exit(1);
					break;
				}
				out[out_len++] = ch;
				break;
			case CharEncodeOct:
				snprintf(out + out_len, OCT_ENCODE_LEN+1, "\\%.3o", ((uint8_t)ch) & 0xFF);
				out_len += OCT_ENCODE_LEN;
				break;
			}
		}
		needed += MIN_SIZE + (str_len - str_off);
	} while(1);
done:
	/* commit written data to block. */
	block->len = out_len;
	out_len -= out_old_len; /* cal. how many bytes written. */
	/* write end quote. */
	rc = CodeBlock_printf(block, "\"");
	if(rc < 0) return rc;
	/* return length of bytes written. */
	return out_len + 2;
}

int CodeBlock_printf(CodeBlock *block, const char *fmt, ...) {
	va_list ap;
	char *str;
	int len;
	int needed;
	int space;
	int rc;

	len = block->len;
	space = block->size - len;
	needed = MIN_SIZE;
	while(1) {
		if(space < needed) {
			grow_CodeBlock(block, needed);
			space = block->size - len;
		}
		str = block->code + len;
		va_start(ap, fmt);
		rc = vsnprintf(str, space, fmt, ap);
		va_end(ap);
		/* check if full message was written. */
		if(rc >= 0 && rc < space) break;
		/* how much space do we need? */
		if(rc > 0 && rc > needed) {
			needed = rc + 1;
		} else {
			needed *= 2;
		}
	}
	if(rc > 0) {
		block->len += rc;
	}
	return rc;
}

void CodeBlock_write_value(CodeBlock *block, const CValue *val) {
	switch(val->type) {
	case VOID:
		break;
	case INTEGER:
	case BOOLEAN:
		CodeBlock_printf(block, "%ld", val->data.num);
		break;
	case DOUBLE:
		CodeBlock_printf(block, "%.30g", val->data.dnum);
		break;
	case STRING:
		CodeBlock_print_quoted_str(block, val->data.str, val->len);
		break;
	case BINARY:
		CodeBlock_print_binary_data(block, val->data.bin, val->len);
		break;
	case CODE:
		CodeBlock_printf(block, "%s", val->data.str);
		break;
	case VARIABLE:
		CodeBlock_printf(block, "%s", val->data.var->name);
		break;
	}
}

void CodeBlock_jump(CodeBlock *block, CodeBlock *desc) {
	assert(CScope_is_func(block->scope));
	CodeBlock_printf(block, "\tgoto block_%s;\n", desc->name);
}

void CodeBlock_cond_jump(CodeBlock *block, CValue *cond, CodeBlock *true_block,
	CodeBlock *false_block)
{
	assert(CScope_is_func(block->scope));
	CodeBlock_printf(block, "\tif(");
		CodeBlock_write_value(block, cond);
	CodeBlock_printf(block, ") {\n\t");
		CodeBlock_jump(block, true_block);
	CodeBlock_printf(block, "\t} else {\n\t");
		CodeBlock_jump(block, false_block);
	CodeBlock_printf(block, "\t}\n");
}

void CodeBlock_call_args(CodeBlock *block, CValue *call, const char *ret,
	CFuncProto *proto, CValues *args)
{
	const CValue *param;
	bool need_comma = false;
	int len;
	int i;
	assert(CScope_is_func(block->scope));

	if(call != NULL && strncasecmp("void", proto->ret_type, 4) != 0) {
		if(ret == NULL) ret = "ret_val";
		CFunc_var(CScope_to_CFunc(block->scope), call, proto->ret_type, ret, NULL);
		CodeBlock_printf(block, "\t%s = ", call->data.var->name);
	} else {
		assert(call == NULL);
		CodeBlock_printf(block, "\t");
	}
	CodeBlock_printf(block, "%s(", proto->name);
	len = args->len;
	for(i = 0; i < len; i++) {
		param = CValues_get(args, i);
		if(need_comma) {
			CodeBlock_printf(block, ", ");
		} else {
			need_comma = true;
		}
		CodeBlock_write_value(block, param);
	}
	CodeBlock_printf(block, ");\n");
}

void CodeBlock_call(CodeBlock *block, CValue *call, const char *ret, CFuncProto *proto, ...)
{
	va_list ap;
	const CValue *param;
	bool need_comma = false;
	assert(CScope_is_func(block->scope));

	if(call != NULL && strncasecmp("void", proto->ret_type, 4) != 0) {
		if(ret == NULL) ret = "ret_val";
		CFunc_var(CScope_to_CFunc(block->scope), call, proto->ret_type, ret, NULL);
		CodeBlock_printf(block, "\t%s = ", call->data.var->name);
	} else {
		assert(call == NULL);
		CodeBlock_printf(block, "\t");
	}
	CodeBlock_printf(block, "%s(", proto->name);
	va_start(ap, proto);
	while((param = va_arg(ap, const CValue *)) != NULL) {
		if(need_comma) {
			CodeBlock_printf(block, ", ");
		} else {
			need_comma = true;
		}
		CodeBlock_write_value(block, param);
	}
	va_end(ap);
	CodeBlock_printf(block, ");\n");
}

void CodeBlock_ret(CodeBlock *block, CValue *ret) {
	assert(CScope_is_func(block->scope));
	CodeBlock_printf(block, "\treturn ");
	CodeBlock_write_value(block, ret);
	CodeBlock_printf(block, ";\n");
}

void CodeBlock_store(CodeBlock *block, const CValue *var, const CValue *val) {
	assert(CScope_is_func(block->scope));
	CodeBlock_printf(block, "\t%s = (", var->data.var->name);
	CodeBlock_write_value(block, val);
	CodeBlock_printf(block, ");\n");
}

void CodeBlock_compare(CodeBlock *block,
	CValue *var, const char *name, const CValue *val1, char *cmp, const CValue *val2)
{
	assert(CScope_is_func(block->scope));
	CFunc_var(CScope_to_CFunc(block->scope), var, "int", name, NULL);
	CodeBlock_printf(block, "\t%s = (", var->data.var->name);
	CodeBlock_write_value(block, val1);
	CodeBlock_printf(block, " %s ", cmp);
	CodeBlock_write_value(block, val2);
	CodeBlock_printf(block, ");\n");
}

void CodeBlock_binop(CodeBlock *block,
	const CValue *var, const CValue *val1, char *op, const CValue *val2)
{
	assert(CScope_is_func(block->scope));
	CodeBlock_printf(block, "\t%s = (", var->data.var->name);
	CodeBlock_write_value(block, val1);
	CodeBlock_printf(block, " %s ", op);
	CodeBlock_write_value(block, val2);
	CodeBlock_printf(block, ");\n");
}

void CodeBlock_var(CodeBlock *block, CValue *val, const char *type, const char *name,
	const CValue *init, bool is_extern)
{
	if(CScope_is_func(block->scope)) {
		CFunc_var(CScope_to_CFunc(block->scope), val, type, name, init);
	} else {
		assert(CScope_is_file(block->scope));
		CScope_var(block->scope, val, type, name);
		CodeBlock_printf(block, "%s %s %s = ", (is_extern) ? "extern" : "static",
			type, val->data.var->name);
		CodeBlock_write_value(block, init);
		CodeBlock_printf(block, ";\n");
	}
}

/**
 *
 * CScope
 *
 */
static void init_CScope(CScope *scope, CScopeType type) {
	scope->head = NULL;
	scope->tail = NULL;
	scope->len = 0;
	scope->vars = 0;
	scope->type = type;
}

CScope *new_CScope() {
	CScope *scope = (CScope *)malloc(sizeof(CScope));
	init_CScope(scope, SCOPE_FILE);
	return scope;
}

static void cleanup_CScope(CScope *scope) {
	free_CodeBlock(scope->head);
	scope->head = NULL;
	scope->tail = NULL;
}

void free_CScope(CScope *scope) {
	cleanup_CScope(scope);
	free(scope);
}

CodeBlock *CScope_create_block(CScope *scope, const char *name, CodeBlock *after) {
	CodeBlock *block;
	scope->len += 1;
	block = new_CodeBlock(scope, name, 1);
	if(after) {
		block->next = after->next;
		after->next = block;
	} else {
		if(scope->tail == NULL) {
			scope->tail = block;
			scope->head = block;
		} else {
			scope->tail->next = block;
			scope->tail = block;
		}
	}
	return block;
}

extern void CScope_var(CScope *scope, CValue *val, const char *type, const char *name) {
	char var_name[8192];
	int var_idx = scope->vars++;
#if USE_VAR_PREFIX
	snprintf(var_name, 8192, "var_%s%d", name, var_idx);
#else
	snprintf(var_name, 8192, "%s%d", name, var_idx);
#endif
	CValue_variable(val, type, var_name);
}

int CScope_dump(CScope *scope, FILE *file) {
	CodeBlock *cur;
	int rc = 0;
	int total = 0;
	/* dump block code. */
	cur = scope->head;
	while(cur != NULL) {
		rc = CodeBlock_dump(cur, file);
		if(rc < 0) return -1;
		total += rc;
		cur = cur->next;
	}
	return total;
}

bool CScope_is_func(CScope *scope) {
	return (scope->type == SCOPE_FUNC);
}

bool CScope_is_file(CScope *scope) {
	return (scope->type == SCOPE_FILE);
}

/**
 *
 * CFunc
 *
 */
CFunc *new_CFunc(const char *ret_type, const char *name) {
	CFunc *func = (CFunc *)malloc(sizeof(CFunc));
	func->proto = new_CFuncProto(ret_type, name, false);
	init_CScope(&(func->scope), SCOPE_FUNC);
	/* create prolog block. */
	func->prolog = new_CodeBlock(&(func->scope), "prolog", 0);
	return func;
}

void free_CFunc(CFunc *func) {
	cleanup_CScope(&(func->scope));
	free_CFuncProto(func->proto);
	free_CodeBlock(func->prolog);
	free(func);
}

CodeBlock *CFunc_create_block(CFunc *func, const char *name) {
	return CScope_create_block(&(func->scope), name, NULL);
}

void CFunc_create_param(CFunc *func, CValue *val, const char *type, const char *name) {
	CFuncProto_create_param(func->proto, val, type, name);
}

void CFunc_var(CFunc *func, CValue *val, const char *type, const char *name, const CValue *init) {
	CScope_var(&(func->scope), val, type, name);
	if(init) {
		CodeBlock_printf(func->prolog, "\t%s %s = ", type, val->data.var->name);
		CodeBlock_write_value(func->prolog, init);
		CodeBlock_printf(func->prolog, ";\n");
	} else {
		CodeBlock_printf(func->prolog, "\t%s %s;\n", type, val->data.var->name);
	}
}

int CFunc_dump(CFunc *func, FILE *file) {
	int rc = 0;
	int total = 0;
	/* gen function prototype. */
	rc = CFuncProto_dump(func->proto, file, false);
	if(rc < 0) return -1;
	total += rc;
	rc = fprintf(file, " {\n");
	if(rc < 0) return -1;
	total += rc;
	/* gen prolog code. */
	rc = CodeBlock_dump(func->prolog, file);
	if(rc < 0) return -1;
	total += rc;
	/* dump function code blocks. */
	CScope_dump(&(func->scope), file);
	/* end function. */
	rc = fprintf(file, "}\n\n");
	if(rc < 0) return -1;
	total += rc;
	return total;
}

