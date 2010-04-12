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
		free(val->data.str);
		val->data.str = NULL;
		break;
	case VARIABLE:
		CVariable_unref(val->data.var);
		val->data.var = NULL;
		break;
	}
	val->type = VOID;
}

void CValue_void(CValue *val) {
	clear_CValue(val);
}

void CValue_boolean(CValue *val, int is_true) {
	clear_CValue(val);
	val->type = BOOLEAN;
	val->data.num = (is_true != 0) ? 1 : 0;
}

void CValue_integer(CValue *val, uint64_t num) {
	clear_CValue(val);
	val->type = INTEGER;
	val->data.num = num;
}

void CValue_double(CValue *val, double dnum) {
	clear_CValue(val);
	val->type = DOUBLE;
	val->data.dnum = dnum;
}

/*
void CValue_string(CValue *val, const char *str) {
	clear_CValue(val);
	val->type = STRING;
	val->data.str = strdup(str);
}
*/

void CValue_variable(CValue *val, const char *type, const char *name) {
	clear_CValue(val);
	val->type = VARIABLE;
	val->data.var = new_CVariable(type, name);
}

void CValue_set(CValue *val, const CValue *new_val) {
	clear_CValue(val);
	val->type = new_val->type;
	switch(val->type) {
	case VOID:
	case INTEGER:
	case BOOLEAN:
	case DOUBLE:
		val->data = new_val->data;
		break;
	case STRING:
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

/*
const CValue *CValues_pop_back(CValues *values) {
	int idx;
	values->len -= 1;
	idx = values->len;
	return &(values->values[idx]);
}
*/

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
static void grow_CodeBlock(CodeBlock *block, int need) {
	int new_size = block->len + need + GROW_SIZE;
	if(new_size < block->size) return;
	block->code = (char *)realloc(block->code, new_size);
	block->size = new_size;
}

CodeBlock *new_CodeBlock(CFunc *parent, const char *name, int write_label) {
	CodeBlock *block = (CodeBlock *)malloc(sizeof(CodeBlock));
	block->parent = parent;
	block->name = strdup(name);
	block->code = NULL;
	block->len = 0;
	block->size = 0;
	grow_CodeBlock(block, 0);
	/* write goto label for code block. */
	if(write_label) {
		CodeBlock_printf(block, "block_%s:\n", name);
	}
	return block;
}

void free_CodeBlock(CodeBlock *block) {
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
		CodeBlock_printf(block, "%f", val->data.dnum);
		break;
	case STRING:
		CodeBlock_printf(block, "\"%s\"", val->data.str);
		break;
	case VARIABLE:
		CodeBlock_printf(block, "%s", val->data.var->name);
		break;
	}
}

void CodeBlock_jump(CodeBlock *block, CodeBlock *desc) {
	CodeBlock_printf(block, "\tgoto block_%s;\n", desc->name);
}

void CodeBlock_cond_jump(CodeBlock *block, CValue *cond, CodeBlock *true_block,
	CodeBlock *false_block)
{
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

	if(call != NULL && strncasecmp("void", proto->ret_type, 4) != 0) {
		if(ret == NULL) ret = "ret_val";
		CFunc_var(block->parent, call, proto->ret_type, ret);
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

	if(call != NULL && strncasecmp("void", proto->ret_type, 4) != 0) {
		if(ret == NULL) ret = "ret_val";
		CFunc_var(block->parent, call, proto->ret_type, ret);
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
	CodeBlock_printf(block, "\treturn ");
	CodeBlock_write_value(block, ret);
	CodeBlock_printf(block, ";\n");
}

void CodeBlock_store(CodeBlock *block, const CValue *var, const CValue *val) {
	CodeBlock_printf(block, "\t%s = (", var->data.var->name);
	CodeBlock_write_value(block, val);
	CodeBlock_printf(block, ");\n");
}

void CodeBlock_compare(CodeBlock *block,
	CValue *var, const char *name, const CValue *val1, char *cmp, const CValue *val2)
{
	CFunc_var(block->parent, var, "int", name);
	CodeBlock_printf(block, "\t%s = (", var->data.var->name);
	CodeBlock_write_value(block, val1);
	CodeBlock_printf(block, " %s ", cmp);
	CodeBlock_write_value(block, val2);
	CodeBlock_printf(block, ");\n");
}

void CodeBlock_binop(CodeBlock *block,
	const CValue *var, const CValue *val1, char *op, const CValue *val2)
{
	CodeBlock_printf(block, "\t%s = (", var->data.var->name);
	CodeBlock_write_value(block, val1);
	CodeBlock_printf(block, " %s ", op);
	CodeBlock_write_value(block, val2);
	CodeBlock_printf(block, ");\n");
}

/**
 *
 * CFunc
 *
 */
static void grow_CFunc(CFunc *func, int need) {
	int new_size = func->len + need;
	int i;
	if(new_size < func->size) return;
	func->blocks = (CodeBlock **)realloc(func->blocks, new_size * sizeof(CodeBlock));
	/* clear new func. */
	for(i = func->size; i < new_size; i++) {
		func->blocks[i] = NULL;
	}
	func->size = new_size;
}

CFunc *new_CFunc(const char *ret_type, const char *name) {
	CFunc *func = (CFunc *)malloc(sizeof(CFunc));
	func->proto = new_CFuncProto(ret_type, name, false);
	func->blocks = NULL;
	func->len = 0;
	func->size = 0;
	func->vars = 0;
	grow_CFunc(func, 0);
	/* create prolog block. */
	func->prolog = new_CodeBlock(func, "prolog", 0);
	return func;
}

void free_CFunc(CFunc *func) {
	int i;
	for(i = func->size - 1; i >= 0; i--) {
		free_CodeBlock(func->blocks[i]);
	}
	free_CFuncProto(func->proto);
	free_CodeBlock(func->prolog);
	free(func->blocks);
	free(func);
}

CodeBlock *CFunc_create_block(CFunc *func, const char *name) {
	CodeBlock *block;
	int idx = func->len;
	grow_CFunc(func, 1);
	func->len += 1;
	block = new_CodeBlock(func, name, 1);
	func->blocks[idx] = block;
	return block;
}

void CFunc_create_param(CFunc *func, CValue *val, const char *type, const char *name) {
	CFuncProto_create_param(func->proto, val, type, name);
}

void CFunc_var(CFunc *func, CValue *val, const char *type, const char *name) {
	char var_name[8192];
	int var_idx = func->vars++;
#if USE_VAR_PREFIX
	snprintf(var_name, 8192, "var_%s%d", name, var_idx);
#else
	snprintf(var_name, 8192, "%s%d", name, var_idx);
#endif
	CodeBlock_printf(func->prolog, "\t%s %s;\n", type, var_name);
	CValue_variable(val, type, var_name);
}

int CFunc_dump(CFunc *func, FILE *file) {
	int len;
	int rc = 0;
	int total = 0;
	int i;
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
	len = func->len;
	for(i = 0; i < len; i++) {
		rc = CodeBlock_dump(func->blocks[i], file);
		if(rc < 0) return -1;
		total += rc;
	}
	rc = fprintf(file, "}\n\n");
	if(rc < 0) return -1;
	total += rc;
	return total;
}

