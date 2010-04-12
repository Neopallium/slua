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

#ifndef codegen_h
#define codegen_h

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>

#define USE_PARAM_PREFIX 0
#define USE_VAR_PREFIX 0

typedef struct CodeBlock CodeBlock;
typedef struct CVariable CVariable;
typedef enum CValueType CValueType;
typedef struct CValue CValue;
typedef struct CValues CValues;
typedef struct CFuncProto CFuncProto;
typedef struct CFunc CFunc;
typedef struct OPFunc OPFunc;

extern void CFunc_var(CFunc *func, CValue *val, const char *type, const char *name);
extern int CodeBlock_printf(CodeBlock *block, const char *fmt, ...);

/**
 *
 * CVariable
 *
 */
struct CVariable {
	char *type;
	char *name;
	int refcount;
};

extern CVariable *new_CVariable(const char *type, const char *name);
extern void CVariable_ref(CVariable *var);

extern void CVariable_unref(CVariable *var);

/**
 *
 * CValueType, CValueData, CValue
 *
 */
enum CValueType {
	VOID = 0,
	INTEGER,
	BOOLEAN,
	DOUBLE,
	STRING,
	VARIABLE,
};

typedef union CValueData {
	uint64_t  num;
	double    dnum;
	char      *str;
	CVariable *var;
} CValueData;

struct CValue {
	CValueType type;
	CValueData data;
};

extern void CValue_void(CValue *val);
extern void CValue_boolean(CValue *val, int is_true);
extern void CValue_integer(CValue *val, uint64_t num);
extern void CValue_double(CValue *val, double dnum);
extern void CValue_string(CValue *val, const char *str);
extern void CValue_variable(CValue *val, const char *type, const char *name);
extern void CValue_set(CValue *val, const CValue *new_val);

/**
 *
 * CValues
 *
 */
struct CValues {
	CValue *values;
	int len;
	int size;
};

extern CValues *new_CValues(int len);
extern void clear_CValues(CValues *values);
extern void free_CValues(CValues *values);
extern void CValues_set(CValues *values, int idx, const CValue *val);
extern const CValue *CValues_get(CValues *values, int idx);
extern void CValues_push_back(CValues *values, const CValue *val);
extern const CValue *CValues_pop_back(CValues *values);

/**
 *
 * CFuncProto
 *
 */
struct CFuncProto {
	char      *ret_type;
	char      *name;
	CValues   *params;
	bool      is_extern;
};

extern CFuncProto *new_CFuncProto(const char *ret_type, const char *name, bool is_extern);
extern void free_CFuncProto(CFuncProto *proto);
extern void CFuncProto_create_param(CFuncProto *proto, CValue *val,
	const char *type, const char *name);
extern CFuncProto *build_CFuncProto(const char *ret_type, const char *name, bool is_extern, ...);
extern int CFuncProto_dump(CFuncProto *proto, FILE *file, bool define);

/**
 *
 * CodeBlock
 *
 */
struct CodeBlock {
	CFunc *parent;
	char *name;  /* code block label. */
	char *code;  /* code block buffer. */
	int  len;    /* length of code written into this block. */
	int  size;   /* size of code block buffer. */
};

extern CodeBlock *new_CodeBlock(CFunc *parent, const char *name, int write_label);
extern void free_CodeBlock(CodeBlock *block);
extern int CodeBlock_dump(CodeBlock *block, FILE *file);
extern int CodeBlock_printf(CodeBlock *block, const char *fmt, ...);
extern void CodeBlock_write_value(CodeBlock *block, const CValue *val);
extern void CodeBlock_jump(CodeBlock *block, CodeBlock *desc);
extern void CodeBlock_cond_jump(CodeBlock *block, CValue *cond, CodeBlock *true_block,
	CodeBlock *false_block);
extern void CodeBlock_call_args(CodeBlock *block, CValue *call, const char *ret,
	CFuncProto *proto, CValues *args);

extern void CodeBlock_call(CodeBlock *block, CValue *call, const char *ret, CFuncProto *proto, ...);
#define CodeBlock_call_void(block, proto, ...) \
	CodeBlock_call(block, NULL, NULL, proto, ##__VA_ARGS__)

extern void CodeBlock_ret(CodeBlock *block, CValue *ret);

extern void CodeBlock_store(CodeBlock *block, const CValue *var, const CValue *val);

extern void CodeBlock_compare(CodeBlock *block,
	CValue *var, const char *name, const CValue *val1, char *cmp, const CValue *val2);

#define CodeBlock_cmp_ne(block, var, name, val1, val2) \
	CodeBlock_compare(block, var, name, val1, "!=", val2)

extern void CodeBlock_binop(CodeBlock *block,
	const CValue *var, const CValue *val1, char *op, const CValue *val2);

#define CodeBlock_add(block, var, val1, val2) \
	CodeBlock_binop(block, var, val1, "+", val2)

#define CodeBlock_sub(block, var, val1, val2) \
	CodeBlock_binop(block, var, val1, "-", val2)

/**
 *
 * CFunc
 *
 */
struct CFunc {
	CFuncProto *proto;
	CodeBlock *prolog;
	CodeBlock **blocks;
	int       len;
	int       size;
	int       vars;
};

extern CFunc *new_CFunc(const char *ret_type, const char *name);

extern void free_CFunc(CFunc *func);

extern CodeBlock *CFunc_create_block(CFunc *func, const char *name);

extern void CFunc_create_param(CFunc *func, CValue *val, const char *type, const char *name);

extern void CFunc_var(CFunc *func, CValue *val, const char *type, const char *name);

extern int CFunc_dump(CFunc *func, FILE *file);

#endif
