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

#include "slua_compiler.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include "lua_vm_ops.h"

#include "lopcodes.h"
#include "lobject.h"
#include "lstate.h"
#include "ldo.h"
#include "lmem.h"

static unsigned int OptLevel = 0;
static bool DisableOpt = false;
static bool OptLevelO1 = false;
static bool OptLevelO2 = false;
static bool OptLevelO3 = false;

#define BRANCH_COND -1
#define BRANCH_NONE -2

typedef struct CVariable {
	char *type;
	char *name;
	int refcount;
} CVariable;

static CVariable *new_CVariable(const char *type, const char *name) {
	CVariable *var = (CVariable *)malloc(sizeof(CVariable));
	var->type = strdup(type);
	var->name = strdup(name);
	var->refcount = 1;
	return var;
}

static void free_CVariable_internal(CVariable *var) {
	free(var->type);
	free(var->name);
	free(var);
}

static void CVariable_ref(CVariable *var) {
	var->refcount++;
}

static void CVariable_unref(CVariable *var) {
	if((var->refcount--) == 0) {
		free_CVariable_internal(var);
	}
}

typedef enum CValueType {
	VOID = 0,
	INTEGER,
	BOOLEAN,
	DOUBLE,
	STRING,
	VARIABLE,
} CValueType;

typedef union CValueData {
	uint64_t  num;
	double    dnum;
	char      *str;
	CVariable *var;
} CValueData;

typedef struct CValue {
	CValueType type;
	CValueData data;
} CValue;

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

static void CValue_void(CValue *val) {
	clear_CValue(val);
}

static void CValue_boolean(CValue *val, int is_true) {
	clear_CValue(val);
	val->type = BOOLEAN;
	val->data.num = (is_true != 0) ? 1 : 0;
}

static void CValue_integer(CValue *val, uint64_t num) {
	clear_CValue(val);
	val->type = INTEGER;
	val->data.num = num;
}

static void CValue_double(CValue *val, double dnum) {
	clear_CValue(val);
	val->type = DOUBLE;
	val->data.dnum = dnum;
}

static void CValue_string(CValue *val, const char *str) {
	clear_CValue(val);
	val->type = STRING;
	val->data.str = strdup(str);
}

static void CValue_variable(CValue *val, const char *type, const char *name) {
	clear_CValue(val);
	val->type = VARIABLE;
	val->data.var = new_CVariable(type, name);
}

static void CValue_set(CValue *val, const CValue *new_val) {
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

typedef struct CValues {
	CValue *values;
	int len;
	int size;
} CValues;

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

static CValues *new_CValues(int len) {
	CValues *values = (CValues *)malloc(sizeof(CValues));
	values->len = len;
	values->size = 0;
	values->values = NULL;
	grow_CValues(values, 0);
	return values;
}

static void clear_CValues(CValues *values) {
	int i;
	for(i = values->size - 1; i >= 0; i--) {
		clear_CValue(&(values->values[i]));
	}
	values->len = 0;
}

static void free_CValues(CValues *values) {
	clear_CValues(values);
	free(values->values);
	free(values);
}

static void CValues_set(CValues *values, int idx, const CValue *val) {
	assert(idx >= 0 && idx < values->len);
	CValue_set(&(values->values[idx]), val);
}

static const CValue *CValues_get(CValues *values, int idx) {
	assert(idx >= 0 && idx < values->len);
	if(values->values[idx].type == VOID) return NULL;
	return &(values->values[idx]);
}

static void CValues_push_back(CValues *values, const CValue *val) {
	int idx = values->len;
	grow_CValues(values, 1);
	CValue_set(&(values->values[idx]), val);
	values->len += 1;
}

static const CValue *CValues_pop_back(CValues *values) {
	int idx;
	values->len -= 1;
	idx = values->len;
	return &(values->values[idx]);
}

typedef struct OPFunc OPFunc;

struct OPFunc {
	const vm_func_info *info;
	OPFunc *next;
};

static OPFunc *new_OPFunc(const vm_func_info *info, OPFunc *next) {
	OPFunc *func = (OPFunc *)malloc(sizeof(OPFunc));
	func->info = info;
	func->next = next;
	return func;
}

static void free_OPFunc(OPFunc *func) {
	OPFunc *next;
	if(func == NULL) return;
	next = func->next;
	free(func);
	free_OPFunc(next);
}

typedef struct CodeBlock CodeBlock;

#define GROW_SIZE 512
#define MIN_SIZE 128
struct CodeBlock {
	char *name;  /* code block label. */
	char *code;  /* code block buffer. */
	int  len;    /* length of code written into this block. */
	int  size;   /* size of code block buffer. */
};

static void grow_CodeBlock(CodeBlock *block, int need) {
	int new_size = block->len + need + GROW_SIZE;
	if(new_size < block->size) return;
	block->code = (char *)realloc(block->code, new_size);
	block->size = new_size;
}

static int CodeBlock_printf(CodeBlock *block, const char *fmt, ...);
static CodeBlock *new_CodeBlock(const char *name, int write_label) {
	CodeBlock *block = (CodeBlock *)malloc(sizeof(CodeBlock));
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

static void free_CodeBlock(CodeBlock *block) {
	free(block->name);
	free(block->code);
	free(block);
}

static int CodeBlock_dump(CodeBlock *block, FILE *file) {
	size_t len;
	len = fwrite(block->code, 1, block->len, file);
	if(len < (size_t)block->len) return -len;
	return len;
}

static int CodeBlock_printf(CodeBlock *block, const char *fmt, ...) {
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

static void CodeBlock_jump(CodeBlock *block, CodeBlock *desc) {
	CodeBlock_printf(block, "\tgoto block_%s;\n", desc->name);
}

typedef struct CFunc {
	CValues   *params;
	CodeBlock *prolog;
	CodeBlock *epilog;
	CodeBlock **blocks;
	char      *ret_type;
	char      *name;
	int       len;
	int       size;
	int       vars;
} CFunc;

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

static CFunc *new_CFunc(const char *ret_type, const char *name) {
	CFunc *func = (CFunc *)malloc(sizeof(CFunc));
	func->ret_type = strdup(ret_type);
	func->name = strdup(name);
	func->params = new_CValues(0);
	func->blocks = NULL;
	func->len = 0;
	func->size = 0;
	func->vars = 0;
	grow_CFunc(func, 0);
	/* create prolog/epilog blocks. */
	func->prolog = new_CodeBlock("prolog", 0);
	func->epilog = new_CodeBlock("epilog", 1);
	return func;
}

static void free_CFunc(CFunc *func) {
	int i;
	for(i = func->size - 1; i >= 0; i--) {
		free_CodeBlock(func->blocks[i]);
	}
	free_CValues(func->params);
	free_CodeBlock(func->prolog);
	free_CodeBlock(func->epilog);
	free(func->blocks);
	free(func);
}

static CodeBlock *CFunc_create_block(CFunc *func, const char *name) {
	CodeBlock *block;
	int idx = func->len;
	grow_CFunc(func, 1);
	func->len += 1;
	block = new_CodeBlock(name, 1);
	func->blocks[idx] = block;
	return block;
}

static void CFunc_create_param(CFunc *func, CValue *val, const char *type, const char *name) {
	char var_name[8192];
	snprintf(var_name, 8192, "param_%s", name);
	CValue_variable(val, type, var_name);
	CValues_push_back(func->params, val);
}

static void CFunc_var(CFunc *func, CValue *val, const char *type, const char *name) {
	char var_name[8192];
	int var_idx = func->vars++;
	snprintf(var_name, 8192, "var_%d_%s", var_idx, name);
	CodeBlock_printf(func->prolog, "\t%s %s;\n", type, var_name);
	CValue_variable(val, type, var_name);
}

static int CFunc_dump(CFunc *func, FILE *file) {
	const CVariable *var;
	const CValue *val;
	int len;
	int rc = 0;
	int total = 0;
	int i;
	/* gen function prototype. */
	rc = fprintf(file, "static %s %s(", func->ret_type, func->name);
	if(rc < 0) return -1;
	/* gen function parameters. */
	len = func->params->len;
	for(i = 0; i < len;) {
		val = CValues_get(func->params, i);
		assert(val->type == VARIABLE);
		var = val->data.var;
		rc = fprintf(file, "%s %s", var->type, var->name);
		if(rc < 0) return -1;
		if((++i) < len) {
			rc = fprintf(file, ", ");
			if(rc < 0) return -1;
		}
	}
	rc = fprintf(file, ") {\n");
	if(rc < 0) return -1;
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

//===----------------------------------------------------------------------===//
// Lua bytecode to LLVM IR compiler
//===----------------------------------------------------------------------===//

void get_proto_constant(CValue *val, TValue *constant) {
	switch(ttype(constant)) {
	case LUA_TBOOLEAN:
		CValue_boolean(val, !l_isfalse(constant));
		break;
	case LUA_TNUMBER:
		CValue_double(val, nvalue(constant));
		break;
	case LUA_TSTRING:
		/* not used. */
		clear_CValue(val);
		break;
	case LUA_TNIL:
	default:
		clear_CValue(val);
		break;
	}
}

static OPFunc *vm_op_funcs[NUM_OPCODES];
static int strip_code = false;

int slua_compiler_main() {
	return 0;
}

SLuaCompiler *slua_new_compiler(lua_State *L, FILE *file, int strip) {
	const vm_func_info *func_info;
	int opcode;
	int i;
	SLuaCompiler *compiler = (SLuaCompiler *)malloc(sizeof(SLuaCompiler));
	compiler->L = L;
	compiler->file = file;
	compiler->strip = strip;

	// set OptLevel
	if(OptLevelO1) OptLevel = 1;
	if(OptLevelO2) OptLevel = 2;
	if(OptLevelO3) OptLevel = 3;
	if(DisableOpt) OptLevel = 0;
	strip_code = strip;

	// create prototype for vm_* functions.
	for(i = 0; i < NUM_OPCODES; i++) vm_op_funcs[i] = NULL; // clear list.
	for(i = 0; true; i++) {
		func_info = &vm_op_functions[i];
		opcode = func_info->opcode;
		if(opcode < 0) break;
		vm_op_funcs[opcode] = new_OPFunc(func_info, vm_op_funcs[opcode]);
	}
	return compiler;
}

void slua_free_compiler(SLuaCompiler *compiler) {
	int i;
	for(i = 0; i < NUM_OPCODES; i++) {
		if(vm_op_funcs[i]) free_OPFunc(vm_op_funcs[i]);
	}
	free(compiler);
}

/*
 * Pre-Compile all loaded functions.
 */
void slua_compiler_compile_all(SLuaCompiler *compiler, Proto *parent) {
	int i;
	/* pre-compile parent */
	slua_compiler_compile(compiler, parent);
	/* pre-compile all children */
	for(i = 0; i < parent->sizep; i++) {
		slua_compiler_compile_all(compiler, parent->p[i]);
	}
}

#define BUF_LEN 8192
void slua_compiler_compile(SLuaCompiler *compiler, Proto *p) {
	Instruction *code=p->code;
	TValue *k=p->k;
	int code_len=p->sizecode;
	OPFunc *opfunc;
	CFunc *func = NULL;
	CodeBlock *true_block=NULL;
	CodeBlock *false_block=NULL;
	CodeBlock *current_block=NULL;
	CodeBlock *entry_block=NULL;
	CodeBlock *ip=NULL;
	CValue *brcond=NULL;
	CValue func_L;
	CValue func_cl;
	CValue func_k;
	const vm_func_info *func_info;
	CValues *args = NULL;
	//llvm::CallInst *call=NULL;
	char buf[BUF_LEN];
	//char locals[LUAI_MAXVARS];
	int strip_ops=0;
	int branch;
	Instruction op_intr;
	int opcode;
	int mini_op_repeat=0;
	int i;
	int len;
	hint_t *op_hints = NULL;
	CValues **op_values = NULL;
	CodeBlock **op_blocks = NULL;
	bool *need_op_block = NULL;
	CValue val;

	// create function.
	strncpy(buf, getstr(p->source), 33);
	// replace non-alphanum characters with '_'
	for(i = 0; i < 33; i++) {
		char c = buf[i];
		if(c == '\0') break;
		if((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			continue;
		}
		if(c == '\n' || c == '\r') {
			buf[i] = '\0';
			break;
		}
		buf[i] = '_';
	}
	buf[i] = '\0';
	len = i;
	snprintf(buf + len, BUF_LEN - len ,"_%d_%d",p->linedefined, p->lastlinedefined);
	func = new_CFunc("int", buf);
	CFunc_create_param(func, &func_L, "lua_State *", "L");
	args = new_CValues(0);
	// entry block
	entry_block = CFunc_create_block(func, "entry");
	ip = entry_block;
	// pre-create basic blocks.
	op_hints      = (hint_t *)calloc(code_len, sizeof(hint_t));
	op_values     = (CValues **)calloc(code_len, sizeof(CValues *));
	op_blocks     = (CodeBlock **)calloc(code_len, sizeof(CodeBlock *));
	need_op_block = (bool *)calloc(code_len, sizeof(bool));
#if 0
	// get LClosure & constants.
	call=Builder.CreateCall(vm_get_current_closure, func_L);
	func_cl=call;
	call=Builder.CreateCall(vm_get_current_constants, func_cl);
	func_k=call;
#endif

	// find all jump/branch destinations and create a new basic block at that opcode.
	// also build hints for some opcodes.
	for(i = 0; i < code_len; i++) {
		need_op_block[i] = true; /* TODO: remove. */
		op_intr=code[i];
		opcode = GET_OPCODE(op_intr);
		// combind simple ops into one function call.
		if(is_mini_vm_op(opcode)) {
			mini_op_repeat++;
		} else {
			if(mini_op_repeat >= 3 && OptLevel > 1) {
				op_hints[i - mini_op_repeat] |= HINT_MINI_VM;
			}
			mini_op_repeat = 0;
		}
		switch (opcode) {
			case OP_LOADBOOL:
				branch = i+1;
				// check C operand if C!=0 then skip over the next op_block.
				if(GETARG_C(op_intr) != 0)
					++branch;
				need_op_block[branch] = true;
				break;
			case OP_LOADK: {
				// check if arg Bx is a number constant.
				TValue *rb = k + INDEXK(GETARG_Bx(op_intr));
				if(ttisnumber(rb)) op_hints[i] |= HINT_Bx_NUM_CONSTANT;
				break;
			}
			case OP_JMP:
				// always branch to the offset stored in operand sBx
				branch = i + 1 + GETARG_sBx(op_intr);
				need_op_block[branch] = true;
				break;
			case OP_TAILCALL:
				branch = i+1;
				need_op_block[0] = true; /* branch to start of function if this is a recursive tail-call. */
				need_op_block[branch] = true; /* branch to return instruction if not recursive. */
				break;
			case OP_EQ:
			case OP_LT:
			case OP_LE:
				// check if arg C is a number constant.
				if(ISK(GETARG_C(op_intr))) {
					TValue *rc = k + INDEXK(GETARG_C(op_intr));
					if(ttisnumber(rc)) op_hints[i] |= HINT_C_NUM_CONSTANT;
				}
				if(GETARG_A(op_intr) == 1) {
					op_hints[i] |= HINT_NOT;
				}
				// fall-through
			case OP_TEST:
			case OP_TESTSET:
			case OP_TFORLOOP:
				branch = ++i + 1;
				op_intr=code[i];
				need_op_block[branch + GETARG_sBx(op_intr)] = true; /* inline JMP op. */
				need_op_block[branch] = true;
				break;
			case OP_FORLOOP:
				branch = i+1;
				need_op_block[branch] = true;
				branch += GETARG_sBx(op_intr);
				need_op_block[branch] = true;
				break;
			case OP_FORPREP:
				branch = i + 1 + GETARG_sBx(op_intr);
				need_op_block[branch] = true;
				need_op_block[branch + 1] = true;
				// test if init/plimit/pstep are number constants.
				if(OptLevel > 1 && i >= 3) {
					lua_Number nums[3];
					bool found_val[3] = { false, false , false };
					bool is_const_num[3] = { false, false, false };
					bool all_longs=true;
					int found=0;
					CValues *vals;
					int forprep_ra = GETARG_A(op_intr);
					bool no_jmp_end_point = true; // don't process ops after finding a jmp end point.
					int x;
					vals = new_CValues(4);
					// find & load constants for init/plimit/pstep
					for(x = 1; x < 6 && found < 3 && no_jmp_end_point; ++x) {
						const TValue *tmp_k;
						Instruction op_intr2;
						int ra;

						if((i - x) < 0) break;
						op_intr2 = code[i - x];
						// get 'a' register.
						ra = GETARG_A(op_intr2);
						ra -= forprep_ra;
						// check for jmp end-point.
						no_jmp_end_point = !(need_op_block[i - x]);
						// check that the 'a' register is for one of the value we are interested in.
						if(ra < 0 || ra > 2) continue;
						// only process this opcode if we haven't seen this value before.
						if(found_val[ra]) continue;
						found_val[ra] = true;
						found++;
						if(GET_OPCODE(op_intr2) == OP_LOADK) {
							tmp_k = k + GETARG_Bx(op_intr2);
							if(ttisnumber(tmp_k)) {
								lua_Number num=nvalue(tmp_k);
								nums[ra] = num;
								// test if number is a whole number
								all_longs &= (floor(num) == num);
								CValue_double(&val, num);
								CValues_set(vals, ra, &val);
								is_const_num[ra] = true;
								op_hints[i - x] |= HINT_SKIP_OP;
								continue;
							}
						}
						all_longs = false;
					}
					all_longs &= (found == 3);
					// create for_idx OP_FORPREP will inialize it.
					op_hints[branch] = HINT_FOR_N_N_N;
					if(all_longs) {
						CFunc_var(func, &val, "uint64_t", "for_idx");
						CValues_set(vals, 3,  &val);
						op_hints[branch] |= HINT_USE_LONG;
					} else {
						CFunc_var(func, &val, "double", "for_idx");
						CValues_set(vals, 3,  &val);
					}
					op_values[branch] = vals;
					// check if step, init, limit are constants
					if(is_const_num[2]) {
						// step is a constant
						if(is_const_num[0]) {
							// init & step are constants.
							if(is_const_num[1]) {
								// all are constants.
								op_hints[i] = HINT_FOR_N_N_N;
							} else {
								// limit is variable.
								op_hints[i] = HINT_FOR_N_M_N;
							}
							op_values[i] = new_CValues(3);
							CValues_set(op_values[i], 0, CValues_get(vals, 0));
							CValues_set(op_values[i], 2, CValues_get(vals, 2));
						} else if(is_const_num[1]) {
							// init is variable, limit & step are constants.
							op_hints[i] = HINT_FOR_M_N_N;
							op_values[i] = new_CValues(3);
							CValues_set(op_values[i], 1, CValues_get(vals, 1));
							CValues_set(op_values[i], 2, CValues_get(vals, 2));
						}
						// check the direct of step.
						if(nums[2] > 0) {
							op_hints[branch] |= HINT_UP;
						} else {
							op_hints[branch] |= HINT_DOWN;
						}
					}
					if(op_hints[i] == HINT_NONE) {
						// don't skip LOADK ops, since we are not inlining them.
						for(x=i-3; x < i; x++) {
							if(op_hints[x] & HINT_SKIP_OP) op_hints[x] &= ~(HINT_SKIP_OP);
						}
					}
					if(all_longs) {
						for(x = 0; x < 3; ++x) {
							CValue_integer(&val, (lua_Long)nums[x]);
							CValues_set(vals, x, &val);
						}
					}
					// make sure OP_FORPREP doesn't subtract 'step' from 'init'
					op_hints[i] |= HINT_NO_SUB;
				}
				break;
			case OP_SETLIST:
				// if C == 0, then next code value is count value.
				if(GETARG_C(op_intr) == 0) {
					i++;
				}
				break;
			case OP_ADD:
			case OP_SUB:
			case OP_MUL:
			case OP_DIV:
			case OP_MOD:
			case OP_POW:
				// check if arg C is a number constant.
				if(ISK(GETARG_C(op_intr))) {
					TValue *rc = k + INDEXK(GETARG_C(op_intr));
					if(ttisnumber(rc)) op_hints[i] |= HINT_C_NUM_CONSTANT;
				}
				break;
			default:
				break;
		}
		// update local variable type hints.
		//vm_op_hint_locals(locals, p->maxstacksize, k, op_intr);
	}
	for(i = 0; i < code_len; i++) {
		if(need_op_block[i]) {
			op_intr=code[i];
			opcode = GET_OPCODE(op_intr);
			snprintf(buf,128,"op_block_%s_%d",luaP_opnames[opcode],i);
			op_blocks[i] = CFunc_create_block(func, buf);
		} else {
			op_blocks[i] = NULL;
		}
	}
	// branch "entry" to first block.
	if(need_op_block[0]) {
		CodeBlock_jump(ip, op_blocks[0]);
	} else {
		current_block = entry_block;
	}
#if 0
	// gen op calls.
	for(i = 0; i < code_len; i++) {
		if(op_blocks[i] != NULL) {
			if(current_block) {
				// add branch to new block.
				CodeBlock_jump(ip, op_blocks[i]);
			}
			ip = op_blocks[i];
			current_block = op_blocks[i];
		}
		// skip dead unreachable code.
		if(current_block == NULL) {
			if(strip_code) strip_ops++;
			continue;
		}
		branch = i+1;
		op_intr=code[i];
		opcode = GET_OPCODE(op_intr);
		opfunc = vm_op_funcs[opcode];
		// combind multiple simple ops into one call.
		if(op_hints[i] & HINT_MINI_VM) {
			int op_count = 1;
			// count mini ops and check for any branch end-points.
			while(is_mini_vm_op(GET_OPCODE(code[i + op_count])) &&
					(op_hints[i + op_count] & HINT_SKIP_OP) == 0) {
				// branch end-point in middle of mini ops block.
				if(need_op_block[i + op_count]) {
					op_hints[i + op_count] |= HINT_MINI_VM; // mark start of new mini vm ops.
					break;
				}
				op_count++;
			}
			if(op_count >= 3) {
				// large block of mini ops add function call to vm_mini_vm()
				Builder.CreateCall4(vm_mini_vm, func_L, func_cl,
					llvm::ConstantInt::get(getCtx(), llvm::APInt(32,op_count)),
					llvm::ConstantInt::get(getCtx(), llvm::APInt(32,i - strip_ops)));
				if(strip_code && strip_ops > 0) {
					while(op_count > 0) {
						code[i - strip_ops] = code[i];
						i++;
						op_count--;
					}
				} else {
					i += op_count;
				}
				i--;
				continue;
			} else {
				// mini ops block too small.
				op_hints[i] &= ~(HINT_MINI_VM);
			}
		}
		// find op function with matching hint.
		while(opfunc->next != NULL && (opfunc->info->hint & op_hints[i]) != opfunc->info->hint) {
			opfunc = opfunc->next;
		}
		//fprintf(stderr, "%d: '%s' (%d) = 0x%08X, hint=0x%X\n", i, luaP_opnames[opcode], opcode, op_intr, op_hints[i]);
		//fprintf(stderr, "%d: func: '%s', func hints=0x%X\n", i, opfunc->info->name,opfunc->info->hint);
		if(op_hints[i] & HINT_SKIP_OP) {
			if(strip_code) strip_ops++;
			continue;
		}
		if(strip_code) {
			// strip all opcodes.
			strip_ops++;
			if(strip_ops > 0 && strip_ops < (i+1)) {
				// move opcodes we want to keep to new position.
				code[(i+1) - strip_ops] = op_intr;
			}
		}
		// setup arguments for opcode function.
		func_info = opfunc->info;
		if(func_info == NULL) {
			fprintf(stderr, "Error missing vm_OP_* function for opcode: %d\n", opcode);
			goto cleanup;
		}
		// special handling of OP_FORLOOP
		if(opcode == OP_FORLOOP) {
			CodeBlock *loop_test;
			CodeBlock *prep_block;
			CodeBlock *incr_block;
			CValue *init,*step,*idx_var,*cur_idx,*next_idx;
			llvm::PHINode *PN;
			CValues *vals;

			vals=op_values[i];
			if(vals != NULL) {
				// get init value from forprep block
				init = CValues_get(vals, 0);
				// get for loop 'idx' variable.
				step = CValues_get(vals, 2);
				idx_var = CValues_get(vals, 3);
				assert(idx_var != NULL);
				incr_block = current_block;
				cur_idx = Builder.CreateLoad(idx_var);
				next_idx = Builder.CreateAdd(cur_idx, step, "next_idx");
				Builder.CreateStore(next_idx, idx_var); // store 'for_init' value.
				// create extra BasicBlock for vm_OP_FORLOOP_*
				snprintf(tmp,128,"op_block_%s_%d_loop_test",luaP_opnames[opcode],i);
				loop_test = CFunc_create_block(func, tmp);
				// create unconditional jmp from current block to loop test block
				CodeBlock_jump(ip, loop_test);
				// create unconditional jmp from forprep block to loop test block
				prep_block = op_blocks[branch + GETARG_sBx(op_intr) - 1];
				ip = prep_block;
				CodeBlock_jump(ip, loop_test);
				// set current_block to loop_test block
				current_block = loop_test;
				ip = current_block;
				// Emit merge block
				if(op_hints[i] & HINT_USE_LONG) {
					PN = Builder.CreatePHI(llvm::Type::getInt64Ty(getCtx()), "idx");
				} else {
					PN = Builder.CreatePHI(llvm::Type::getDoubleTy(getCtx()), "idx");
				}
				PN->addIncoming(init, prep_block);
				PN->addIncoming(next_idx, incr_block);
				CValues_set(vals, 0,  PN);
			}
		}
		clear_CValues(args);
		for(int x = 0; func_info->params[x] != VAR_T_VOID ; x++) {
			switch(func_info->params[x]) {
			case VAR_T_ARG_A:
				CValue_integer(&val, GETARG_A(op_intr));
				break;
			case VAR_T_ARG_C:
				CValue_integer(&val, GETARG_C(op_intr));
				break;
			case VAR_T_ARG_C_FB2INT:
				CValue_integer(&val, luaO_fb2int(GETARG_C(op_intr)));
				break;
			case VAR_T_ARG_Bx_NUM_CONSTANT:
				get_proto_constant(val, k + INDEXK(GETARG_Bx(op_intr)));
				break;
			case VAR_T_ARG_C_NUM_CONSTANT:
				get_proto_constant(val, k + INDEXK(GETARG_C(op_intr)));
				break;
			case VAR_T_ARG_C_NEXT_INSTRUCTION: {
				int c = GETARG_C(op_intr);
				// if C == 0, then next code value is used as ARG_C.
				if(c == 0) {
					if((i+1) < code_len) {
						c = code[i+1];
						if(strip_code) strip_ops++;
					}
				}
				CValue_integer(&val, c);
				break;
			}
			case VAR_T_ARG_B:
				CValue_integer(&val, GETARG_B(op_intr));
				break;
			case VAR_T_ARG_B_FB2INT:
				CValue_integer(&val, luaO_fb2int(GETARG_B(op_intr)));
				break;
			case VAR_T_ARG_Bx:
				CValue_integer(&val, GETARG_Bx(op_intr));
				break;
			case VAR_T_ARG_sBx:
				CValue_integer(&val, GETARG_sBx(op_intr));
				break;
			case VAR_T_PC_OFFSET:
				CValue_integer(&val, i + 1 - strip_ops);
				break;
			case VAR_T_INSTRUCTION:
				CValue_integer(&val, op_intr);
				break;
			case VAR_T_NEXT_INSTRUCTION:
				CValue_integer(&val, code[i+1]);
				break;
			case VAR_T_LUA_STATE_PTR:
				val = func_L;
				break;
			case VAR_T_K:
				val = func_k;
				break;
			case VAR_T_CL:
				val = func_cl;
				break;
			case VAR_T_OP_VALUE_0:
				if(op_values[i] != NULL) set_Value(val, CValues_set(op_values[i], 0));
				break;
			case VAR_T_OP_VALUE_1:
				if(op_values[i] != NULL) set_Value(val, CValues_set(op_values[i], 1));
				break;
			case VAR_T_OP_VALUE_2:
				if(op_values[i] != NULL) set_Value(val, CValues_set(op_values[i], 2));
				break;
			default:
				fprintf(stderr, "Error: not implemented!\n");
				goto cleanup;
			case VAR_T_VOID:
				fprintf(stderr, "Error: invalid value type!\n");
				goto cleanup;
			}
			if(val == NULL) {
				fprintf(stderr, "Error: Missing parameter '%d' for this opcode(%d) function=%s!\n", x,
					opcode, func_info->name);
				exit(1);
			}
			CValues_push_back(args, val);
		}
		// create call to opcode function.
		if(func_info->ret_type != VAR_T_VOID) {
			call=Builder.CreateCall(opfunc->func, args.begin(), args.end(), "retval");
		} else {
			call=Builder.CreateCall(opfunc->func, args.begin(), args.end());
		}
		// handle retval from opcode function.
		switch (opcode) {
			case OP_LOADBOOL:
				// check C operand if C!=0 then skip over the next op_block.
				if(GETARG_C(op_intr) != 0) branch += 1;
				else branch = BRANCH_NONE;
				break;
			case OP_LOADK:
			case OP_LOADNIL:
			case OP_GETGLOBAL:
			case OP_GETTABLE:
			case OP_SETGLOBAL:
			case OP_SETTABLE:
			case OP_NEWTABLE:
			case OP_SELF:
			case OP_ADD:
			case OP_SUB:
			case OP_MUL:
			case OP_DIV:
			case OP_MOD:
			case OP_POW:
			case OP_UNM:
			case OP_NOT:
			case OP_LEN:
			case OP_CONCAT:
			case OP_GETUPVAL:
			case OP_MOVE:
				branch = BRANCH_NONE;
				break;
			case OP_CLOSE:
			case OP_SETUPVAL:
				branch = BRANCH_NONE;
				break;
			case OP_VARARG:
			case OP_CALL:
				branch = BRANCH_NONE;
				break;
			case OP_TAILCALL:
				//call->setTailCall(true);
				brcond=call;
				brcond=Builder.CreateICmpNE(brcond,
						llvm::ConstantInt::get(getCtx(), llvm::APInt(32, PCRTAILRECUR)), "brcond");
				i++; // skip return opcode.
				false_block = op_blocks[0]; // branch to start of function if this is a recursive tail-call.
				true_block = op_blocks[i]; // branch to return instruction if not recursive.
				Builder.CreateCondBr(brcond, true_block, false_block);
				ip = op_blocks[i];
				Builder.CreateRet(call);
				current_block = NULL; // have terminator
				branch = BRANCH_NONE;
				break;
			case OP_JMP:
				// always branch to the offset stored in operand sBx
				branch += GETARG_sBx(op_intr);
				// call vm_OP_JMP just in case luai_threadyield is defined.
				break;
			case OP_EQ:
			case OP_LT:
			case OP_LE:
			case OP_TEST:
			case OP_TESTSET:
			case OP_TFORLOOP:
				brcond=call;
				brcond=Builder.CreateICmpNE(brcond, llvm::ConstantInt::get(getCtx(), llvm::APInt(32,0)), "brcond");
				false_block=op_blocks[branch+1];
				/* inlined JMP op. */
				branch = ++i + 1;
				if(strip_code) {
					strip_ops++;
					if(strip_ops > 0 && strip_ops < (i+1)) {
						// move opcodes we want to keep to new position.
						code[(i+1) - strip_ops] = code[i];
					}
				}
				op_intr=code[i];
				branch += GETARG_sBx(op_intr);
				true_block=op_blocks[branch];
				branch = BRANCH_COND; // do conditional branch
				break;
			case OP_FORLOOP: {
				llvm::Function *set_func=vm_set_number;
				llvm::CallInst *call2;
				CValues *vals;

				brcond=call;
				brcond=Builder.CreateICmpNE(brcond, llvm::ConstantInt::get(getCtx(), llvm::APInt(32,0)), "brcond");
				true_block=op_blocks[branch + GETARG_sBx(op_intr)];
				false_block=op_blocks[branch];
				branch = BRANCH_COND; // do conditional branch

				// update external index if needed.
				vals=op_values[i];
				if(vals != NULL) {
					CodeBlock *idx_block;
					if(op_hints[i] & HINT_USE_LONG) {
						set_func = vm_set_long;
					}
					// create extra BasicBlock
					snprintf(tmp,128,"op_block_%s_%d_set_for_idx",luaP_opnames[opcode],i);
					idx_block = CFunc_create_block(func, tmp);
					ip = idx_block;
					// copy idx value to Lua-stack.
					call2=Builder.CreateCall3(set_func,func_L,
						llvm::ConstantInt::get(getCtx(), llvm::APInt(32,(GETARG_A(op_intr) + 3))), CValues_get(vals, 0));
					// create jmp to true_block
					CodeBlock_jump(ip, true_block);
					true_block = idx_block;
					ip = current_block;
				}
				break;
			}
			case OP_FORPREP: {
				llvm::Function *get_func=vm_get_number;
				CValue *idx_var,*init;
				llvm::CallInst *call2;
				CValues *vals;

				op_blocks[i] = current_block;
				branch += GETARG_sBx(op_intr);
				vals=op_values[branch];
				// if no saved value, then use slow method.
				if(vals == NULL) break;
				if(op_hints[branch] & HINT_USE_LONG) {
					get_func = vm_get_long;
				}
				// get non-constant init from Lua stack.
				if(CValues_get(vals, 0) == NULL) {
					call2=Builder.CreateCall2(get_func,func_L,
						llvm::ConstantInt::get(getCtx(), llvm::APInt(32,(GETARG_A(op_intr) + 0))), "for_init");
					CValues_set(vals, 0,  call2);
				}
				init = CValues_get(vals, 0);
				// get non-constant limit from Lua stack.
				if(CValues_get(vals, 1) == NULL) {
					call2=Builder.CreateCall2(get_func,func_L,
						llvm::ConstantInt::get(getCtx(), llvm::APInt(32,(GETARG_A(op_intr) + 1))), "for_limit");
					CValues_set(vals, 1,  call2);
				}
				// get non-constant step from Lua stack.
				if(CValues_get(vals, 2) == NULL) {
					call2=Builder.CreateCall2(get_func,func_L,
						llvm::ConstantInt::get(getCtx(), llvm::APInt(32,(GETARG_A(op_intr) + 2))), "for_step");
					CValues_set(vals, 2,  call2);
				}
				// get for loop 'idx' variable.
				assert(CValues_get(vals, 3) != NULL);
				idx_var = CValues_get(vals, 3);
				Builder.CreateStore(init, idx_var); // store 'for_init' value.
				CValues_set(vals, 0, init);
				current_block = NULL; // have terminator
				branch = BRANCH_NONE;
				break;
			}
			case OP_SETLIST:
				// if C == 0, then next code value is used as ARG_C.
				if(GETARG_C(op_intr) == 0) {
					i++;
				}
				branch = BRANCH_NONE;
				break;
			case OP_CLOSURE: {
				Proto *p2 = p->p[GETARG_Bx(op_intr)];
				int nups = p2->nups;
				if(strip_code && strip_ops > 0) {
					while(nups > 0) {
						i++;
						code[i - strip_ops] = code[i];
						nups--;
					}
				} else {
					i += nups;
				}
				branch = BRANCH_NONE;
				break;
			}
			case OP_RETURN: {
				call->setTailCall(true);
				Builder.CreateRet(call);
				branch = BRANCH_NONE;
				current_block = NULL; // have terminator
				break;
			}
			default:
				fprintf(stderr, "Bad opcode: opcode=%d\n", opcode);
				break;
		}
		// branch to next block.
		if(branch >= 0 && branch < code_len) {
			CodeBlock_jump(ip, op_blocks[branch]);
			current_block = NULL; // have terminator
		} else if(branch == BRANCH_COND) {
			Builder.CreateCondBr(brcond, true_block, false_block);
			current_block = NULL; // have terminator
		}
	}
	// strip Lua bytecode and debug info.
	if(strip_code && strip_ops > 0) {
		code_len -= strip_ops;
		luaM_reallocvector(L, p->code, p->sizecode, code_len, Instruction);
		p->sizecode = code_len;
		luaM_reallocvector(L, p->lineinfo, p->sizelineinfo, 0, int);
		p->sizelineinfo = 0;
		luaM_reallocvector(L, p->locvars, p->sizelocvars, 0, LocVar);
		p->sizelocvars = 0;
		luaM_reallocvector(L, p->upvalues, p->sizeupvalues, 0, TString *);
		p->sizeupvalues = 0;
	}
#endif
	/* dump functions C code. */
	CFunc_dump(func, compiler->file);
cleanup:
	if(op_values) {
		for(i = 0; i < code_len; i++) {
			if(op_values[i]) {
				free_CValues(op_values[i]);
			}
		}
		free(op_values);
	}
	if(op_hints) free(op_hints);
	if(op_blocks) free(op_blocks);
	if(need_op_block) free(need_op_block);

	if(func) free_CFunc(func);
	if(args) free_CValues(args);
}

