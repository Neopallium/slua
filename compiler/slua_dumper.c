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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "slua_compiler.h"
#include "slua_dumper.h"
#include "codegen.h"

#include "lstate.h"
#include "load_jit_proto.h"

static bool LuaModule = false;

//===----------------------------------------------------------------------===//
// Dump a compilable C code module.
//===----------------------------------------------------------------------===//

void dump_constants(CScope *scope, CodeBlock *block, CValue *constants, Proto *p) {
	CValue val = { .type = VOID };
	CValue val2 = { .type = VOID };
	TValue *tval;
	int const_type = 0;
	int const_length = 0;
	char *field;
	int i;

	/* generate constants array. */
	CScope_var(scope, constants, "constant_type", "constants");
	CodeBlock_printf(block, "static constant_type %s[] = {\n", constants->data.var->name);

	for(i = 0; i < p->sizek; i++) {
		tval = &(p->k[i]);
		const_length = 0;

		switch(ttype(tval)) {
			case LUA_TSTRING:
				const_type = TYPE_STRING;
				const_length = tsvalue(tval)->len;
				field = ".str";
				CValue_string(&val, svalue(tval));
				break;
			case LUA_TBOOLEAN:
				const_type = TYPE_BOOLEAN;
				field = ".b";
				CValue_boolean(&val, !l_isfalse(tval));
				break;
			case LUA_TNUMBER:
				const_type = TYPE_NUMBER;
				field = ".num";
				CValue_double(&val, nvalue(tval));
				break;
			case LUA_TNIL:
			default:
				const_type = TYPE_NIL;
				field = ".str";
				CValue_code(&val, "NULL");
				break;
		}
		CodeBlock_printf(block, "\t{ ");
		CValue_integer(&val2, const_type);
		CodeBlock_write_value(block, &val2);
		CodeBlock_printf(block, ",");
		CValue_integer(&val2, const_length);
		CodeBlock_write_value(block, &val2);
		CodeBlock_printf(block, ", { %s = ", field);
		CodeBlock_write_value(block, &val);
		CodeBlock_printf(block, "} },\n");
	}

	CodeBlock_printf(block, "};\n");

	CValue_void(&val);
	CValue_void(&val2);
}

void dump_locvars(CScope *scope, CodeBlock *block, CValue *locvars, Proto *p) {
	CValue val = { .type = VOID };
	LocVar *locvar;
	int i;

	/* generate locvars array. */
	CScope_var(scope, locvars, "jit_LocVar", "locvars");
	CodeBlock_printf(block, "static jit_LocVar %s[] = {\n", locvars->data.var->name);

	for(i = 0; i < p->sizelocvars; i++) {
		locvar = &(p->locvars[i]);
		CodeBlock_printf(block, "\t{ ");
		CValue_string(&val, getstr(locvar->varname));
		CodeBlock_write_value(block, &val);
		CodeBlock_printf(block, ",");
		CValue_integer(&val, locvar->startpc);
		CodeBlock_write_value(block, &val);
		CodeBlock_printf(block, ",");
		CValue_integer(&val, locvar->endpc);
		CodeBlock_write_value(block, &val);
		CodeBlock_printf(block, " },\n");
	}

	CodeBlock_printf(block, "};\n");

	CValue_void(&val);
}

void dump_upvalues(CScope *scope, CodeBlock *block, CValue *upvalues, Proto *p) {
	CValue val = { .type = VOID };
	int i;

	/* generate upvalues array. */
	CScope_var(scope, upvalues, "char *", "upvalues");
	CodeBlock_printf(block, "static char *%s[] = {\n", upvalues->data.var->name);

	for(i = 0; i < p->sizeupvalues; i++) {
		CodeBlock_printf(block, "\t");
		CValue_string(&val, getstr(p->upvalues[i]));
		CodeBlock_write_value(block, &val);
		CodeBlock_printf(block, ",\n");
	}

	CodeBlock_printf(block, "};\n");

	CValue_void(&val);
}

#define BUF_LEN 512
void get_compiled_function(CValue *val, Proto *p) {
	char buf[BUF_LEN];

	slua_compiler_proto_name(p, buf, BUF_LEN);
	CValue_variable(val, "lua_CFunction", buf);
}

void dump_proto(CScope *scope, CodeBlock *globals, CodeBlock *block, Proto *p) {
	CodeBlock *sub_block;
	CValue val = { .type = VOID };
	CValue val2 = { .type = VOID };
	CValues *fields;
	const CValue *field;
	int i;

	sub_block = CScope_create_block(scope, "proto_data", globals);

	fields = new_CValues(0);

	// name
	CValue_string(&val, getstr(p->source));
	CValues_push_back(fields, &val);
	// jit_func
	get_compiled_function(&val, p);
	CValues_push_back(fields, &val);
	// linedefined
	CValue_integer(&val, p->linedefined);
	CValues_push_back(fields, &val);
	// lastlinedefined
	CValue_integer(&val, p->lastlinedefined);
	CValues_push_back(fields, &val);
	// nups
	CValue_integer(&val, p->nups);
	CValues_push_back(fields, &val);
	// numparams
	CValue_integer(&val, p->numparams);
	CValues_push_back(fields, &val);
	// is_vararg
	CValue_integer(&val, p->is_vararg);
	CValues_push_back(fields, &val);
	// maxstacksize
	CValue_integer(&val, p->maxstacksize);
	CValues_push_back(fields, &val);
	// sizek
	CValue_integer(&val, p->sizek);
	CValues_push_back(fields, &val);
	// sizelocvars
	CValue_integer(&val, p->sizelocvars);
	CValues_push_back(fields, &val);
	// sizeupvalues
	CValue_integer(&val, p->sizeupvalues);
	CValues_push_back(fields, &val);
	// sizep
	CValue_integer(&val, p->sizep);
	CValues_push_back(fields, &val);
	// sizecode
	CValue_integer(&val, p->sizecode);
	CValues_push_back(fields, &val);
	// sizelineinfo
	CValue_integer(&val, p->sizelineinfo);
	CValues_push_back(fields, &val);
	// k
	if(p->sizek > 0) {
		dump_constants(scope, sub_block, &val, p);
	} else {
		CValue_void(&val);
	}
	CValues_push_back(fields, &val);
	// locvars
	if(p->sizelocvars) {
		dump_locvars(scope, sub_block, &val, p);
	} else {
		CValue_void(&val);
	}
	CValues_push_back(fields, &val);
	// upvalues
	if(p->sizeupvalues) {
		dump_upvalues(scope, sub_block, &val, p);
	} else {
		CValue_void(&val);
	}
	CValues_push_back(fields, &val);
	// p
	if(p->sizep > 0) {
		CScope_var(scope, &val, "jit_proto *", "sub_protos");
		CodeBlock_printf(sub_block, "static jit_proto %s[] = {\n", val.data.var->name);
		for(i = 0; i < p->sizep; i++) {
			dump_proto(scope, globals, sub_block, p->p[i]);
			CodeBlock_write_value(block, &val2);
			CodeBlock_printf(sub_block, ",\n");
		}
		CodeBlock_printf(sub_block, "};\n");
	} else {
		CValue_void(&val);
	}
	CValues_push_back(fields, &val);
	// code
	if(p->sizecode > 0) {
		CScope_var(scope, &val, "uint32_t", "proto_code");
		CodeBlock_printf(sub_block, "static uint32_t %s[] = {\n", val.data.var->name);
		for(i = 0; i < p->sizecode; i++) {
			CodeBlock_printf(sub_block, "\t");
			CValue_integer(&val2, p->code[i]);
			CodeBlock_write_value(sub_block, &val2);
			CodeBlock_printf(sub_block, ",\n");
		}
		CodeBlock_printf(sub_block, "};\n");
	} else {
		CValue_void(&val);
	}
	CValues_push_back(fields, &val);
	// lineinfo
	if(p->sizelineinfo > 0) {
		CScope_var(scope, &val, "uint32_t", "proto_lineinfo");
		CodeBlock_printf(sub_block, "static uint32_t %s[] = {\n", val.data.var->name);
		for(i = 0; i < p->sizelineinfo; i++) {
			CodeBlock_printf(sub_block, "\t");
			CValue_integer(&val2, p->lineinfo[i]);
			CodeBlock_write_value(sub_block, &val2);
			CodeBlock_printf(sub_block, ",\n");
		}
		CodeBlock_printf(sub_block, "};\n");
	} else {
		CValue_void(&val);
	}
	CValues_push_back(fields, &val);

	/* generate jit_proto info. */
	CodeBlock_printf(block, "{\n");
	for(i = 0; i < fields->len; i++) {
		CodeBlock_printf(block, "\t");
		field = CValues_get(fields, i);
		if(field) {
			CodeBlock_write_value(block, field);
		} else {
			CodeBlock_printf(block, "NULL");
		}
		CodeBlock_printf(block, ",\n");
	}
	CodeBlock_printf(block, "}");

	CValue_void(&val);
	CValue_void(&val2);
	free_CValues(fields);
}

void dump_protos(CScope *scope, CodeBlock *globals, CValue *proto_init, Proto *p, bool is_extern) {
	CodeBlock *block;
	CValue val = { .type = VOID };
	char *var_name = "module_proto_init";
	if(is_extern) {
		var_name = "jit_proto_init";
	}

	// dump all proto info.
	block = CScope_create_block(scope, "proto_block", globals);
	CValue_variable(proto_init, "jit_proto", var_name);
	CodeBlock_printf(block, "%s jit_proto %s = ", (is_extern) ? "" : "static", var_name);
	dump_proto(scope, globals, block, p);
	CodeBlock_printf(block, ";\n");

	if(!is_extern) {
		CValue_code(proto_init, "&(module_proto_init)");
	}
	CValue_void(&val);
}

CFunc *dump_standalone(CScope *scope, Proto *p) {
	CValue gjit_proto_init = { .type = VOID };
	CodeBlock *block;

	//
	// dump protos to a global variable for re-loading.
	//
	block = CScope_create_block(scope, "standalone", NULL);
	dump_protos(scope, block, &gjit_proto_init, p, true);

	CValue_void(&gjit_proto_init);
	return NULL;
}

#define MAX_MODULE_NAME_LEN 100
#define BUF_LEN 512
CFunc *dump_lua_module(CScope *scope, Proto *p, const char *mod_name) {
	CFunc *func;
	CFuncProto *load_compiled_module_func;
	CodeBlock *block=NULL;
	CodeBlock *ip;
	CValue gjit_proto_init = { .type = VOID };
	CValue func_L = { .type = VOID };
	CValue call = { .type = VOID };
	char buf[BUF_LEN] = "luaopen_";
	int len;
	int n;

	//
	// dump protos to a static variable for re-loading.
	//
	block = CScope_create_block(scope, "lua_module", NULL);
	dump_protos(scope, block, &gjit_proto_init, p, false);

	//
	// normalize mod_name.
	//
	len = strlen(buf);
	strncpy(buf + len, mod_name, MAX_MODULE_NAME_LEN);
	len = strlen(buf);
	// remove '.c' from end of mod_name.
	if(len > 2) {
		if(buf[len - 2] == '.') {
			if(buf[len - 1] == 'c' || buf[len - 1] == 'C') {
				len -= 2;
				buf[len] = '\0';
			}
		}
	}
	// convert non-alphanum chars to '_'
	for(n = 0; n < len && buf[n] != '\0'; n++) {
		char c = buf[n];
		if((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) continue;
		if(c == '\n' || c == '\r') {
			buf[n] = '\0';
			break;
		}
		buf[n] = '_';
	}
	len = n;

	//
	// dump 'luaopen_<mod_name>' for loading the module.
	//
	func = new_CFunc("int", buf);
	// name arg1 = "L"
	CFunc_create_param(func, &func_L, "lua_State *", "L");
	// entry block
	block = CFunc_create_block(func, "entry");
	ip = block;
	// call 'load_compiled_module'
	load_compiled_module_func = build_CFuncProto("int", "load_compiled_module", true,
		"lua_State *", "L", "jit_proto *", "p", NULL);
	CodeBlock_call(ip, &call, "ret", load_compiled_module_func, &(func_L), &(gjit_proto_init), NULL);
	CodeBlock_ret(ip, &call);

	free_CFuncProto(load_compiled_module_func);
	CValue_void(&call);
	CValue_void(&func_L);
	CValue_void(&gjit_proto_init);
	return func;
}

void slua_dumper_dump(FILE *file, const char *output, lua_State *L, Proto *p, int stripping) {
	SLuaCompiler *compiler;
	CScope *scope;
	CFunc *func = NULL;

	/* generate includes. */
	fprintf(file,
	"#include <stdint.h>\n#include \"lua_vm_ops.c\"\n#include \"load_jit_proto.h\"\n\n");

	compiler = slua_new_compiler(L, file, stripping);
	slua_compiler_compile_all(compiler, p);
	scope = new_CScope();
	if(LuaModule) {
		// Dump proto info to static variable and create 'luaopen_<mod_name>' function.
		func = dump_lua_module(scope, p, output);
	} else {
		// Dump proto info to global for standalone exe.
		func = dump_standalone(scope, p);
	}
	CScope_dump(scope, file);
	if(func) {
		CFunc_dump(func, file);
		free_CFunc(func);
	}
	free_CScope(scope);
	slua_free_compiler(compiler);
}

