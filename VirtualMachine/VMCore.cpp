#include "VMCore.h"
#include <string>
#include <iostream>

VMCore::VMCore()
{
	memorySector = nullptr;
	programSector = nullptr;
	pHeader = nullptr;
	cpu = {};
}

void VMCore::load(byte* raw, DWORD rawSize)
{
	programSector = new byte[rawSize];
	memorySector = new byte[rawSize];

	while (!stack.empty())
		stack.pop();

	ZeroMemory(programSector, rawSize);

	memcpy(programSector, raw, rawSize);

	pHeader = reinterpret_cast<VM_HEADER*>(programSector);
	if (pHeader->magic != 0x1337)
		exit(0);

	memorySector = new byte[pHeader->memoryAlloc];
	ZeroMemory(memorySector, pHeader->memoryAlloc);
}

void VMCore::exec()
{
	byte* opcodes = (programSector + sizeof(VM_HEADER));
	cpu.eip = reinterpret_cast<DWORD>(opcodes);
	OPCODE* opcode;
	do
	{
		opcode = reinterpret_cast<OPCODE*>(cpu.eip);
		translate(opcode);
		cpu.eip += sizeof(OPCODE);

	} while (opcode->command != OPCODE_END);

}

void VMCore::set_reg_value(const REGISTER_IDS& reg, const DWORD& val)
{
	switch(reg)
	{
	case REG_EAX:
		cpu.eax = val;
		break;
	case REG_EBX:
		cpu.ebx = val;
		break;
	case REG_ECX:
		cpu.ecx = val;
		break;
	case REG_EDX:
		cpu.edx = val;
	default:
		break;
	}
}

DWORD VMCore::get_reg_value(const REGISTER_IDS& reg) const
{
	switch (reg)
	{
	case REG_EAX:
		return cpu.eax;
	case REG_EBX:
		return cpu.ebx;
	case REG_ECX:
		return cpu.ecx;
	case REG_EDX:
		return cpu.edx;
	default:
		return  0;
	}
}

void VMCore::translate(const OPCODE* opcode)
{
	switch (opcode->command)
	{
	case OPCODE_NOP:
	case OPCODE_END:
		break;

	case OPCODE_MOV_REG_VAL:
	case OPCODE_MOV_REG_REG:
	case OPCODE_MOV_REGMEM_VAL:
	case OPCODE_MOV_REG_REGMEM:
	case OPCODE_MOV_MEM_VAL:
	case OPCODE_MOV_MEM_REG:
	case OPCODE_MOV_REG_MEM:
		translate_mov(opcode);
		break;

	case OPCODE_PUSH_VAL:
	case OPCODE_PUSH_REG:
	case OPCODE_PUSH_REGMEM:
		translate_push(opcode);
		break;

	case OPCODE_POP_REG:
	case OPCODE_POP_REGMEM:
	case OPCODE_POP_MEM:
		translate_pop(opcode);
		break;

	case OPCODE_ADD_REG_REG:
	case OPCODE_ADD_REG_VAL:
	case OPCODE_ADD_REG_MEM:
	case OPCODE_ADD_REGMEM_VAL:
	case OPCODE_ADD_REGMEM_REG:
		translate_add(opcode);
		break;

	case OPCODE_SUB_REG_REG:
	case OPCODE_SUB_REG_VAL:
	case OPCODE_SUB_REG_MEM:
	case OPCODE_SUB_REGMEM_VAL:
	case OPCODE_SUB_REGMEM_REG:
		translate_sub(opcode);
		break;

	case OPCODE_MUL_REG_REG:
	case OPCODE_MUL_REG_VAL:
	case OPCODE_MUL_REG_MEM:
	case OPCODE_MUL_REGMEM_VAL:
	case OPCODE_MUL_REGMEM_REG:
		translate_mul(opcode);
		break;

	case OPCODE_XOR_REG_REG:
	case OPCODE_XOR_REG_VAL:
	case OPCODE_XOR_REG_MEM:
	case OPCODE_XOR_REGMEM_VAL:
	case OPCODE_XOR_REGMEM_REG:
		translate_xor(opcode);
		break;

	case OPCODE_AND_REG_REG:
	case OPCODE_AND_REG_VAL:
	case OPCODE_AND_REG_MEM:
	case OPCODE_AND_REGMEM_VAL:
	case OPCODE_AND_REGMEM_REG:
		translate_and(opcode);
		break;

	case OPCODE_NOT_REG:
	case OPCODE_NOT_REGMEM:
	case OPCODE_NOT_MEM:
		translate_not(opcode);
		break;

	case OPCODE_PUTCHAR:
		translate_putchar(opcode);
		break;

	case OPCODE_GETCHAR:
		translate_getchar(opcode);
		break;

	case OPCODE_MAKE_INTERRUPT:
	case OPCODE_DROP_INTERRUPT:
	case OPCODE_MAKE_LABEL:
		translate_interrupts(opcode);
		break;

	case OPCODE_CMP_REG_REG:
	case OPCODE_CMP_REG_VAL:
	case OPCODE_CMP_REGMEM_VAL:
	case OPCODE_CMP_REG_MEM:
		translate_cmp(opcode);
		break;

	case OPCODE_JMP_INTERRUPT:
	case OPCODE_JMP_LABEL:
		translate_jmp(opcode);
		break;

	case OPCODE_JNZ_LABEL:
	case OPCODE_JNZ_INTERRUPT:
		translate_jnz(opcode);
		break;

	case OPCODE_JZ_INTERRUPT:
	case OPCODE_JZ_LABEL:
		translate_jz(opcode);
		break;
	default:
		break;
	}
}

void VMCore::translate_mov(const OPCODE* opcode)
{
	switch(opcode->command)
	{
	case OPCODE_MOV_REG_VAL:
		set_reg_value(static_cast<REGISTER_IDS>(opcode->lParam), opcode->rParam);
		break;
	case OPCODE_MOV_REG_REG:
		set_reg_value(static_cast<REGISTER_IDS>(opcode->lParam), get_reg_value(static_cast<REGISTER_IDS>(opcode->rParam)));
		break;
	case OPCODE_MOV_REGMEM_VAL:
		set_memory_value(get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam)), opcode->rParam);
		break;
	case OPCODE_MOV_REG_REGMEM:
		set_reg_value(static_cast<REGISTER_IDS>(opcode->lParam), get_memory_value<DWORD>(get_reg_value(static_cast<REGISTER_IDS>(opcode->rParam))));
		break;
	case OPCODE_MOV_MEM_VAL:
		set_memory_value(static_cast<REGISTER_IDS>(opcode->lParam), opcode->rParam);
		break;
	case OPCODE_MOV_MEM_REG:
		set_memory_value(static_cast<REGISTER_IDS>(opcode->lParam), get_reg_value(static_cast<REGISTER_IDS>(opcode->rParam)));
		break;
	case OPCODE_MOV_REG_MEM:
		set_reg_value((REGISTER_IDS)opcode->lParam, get_memory_value<DWORD>(opcode->rParam));
		break;
	default:
		break;
	}
}

void VMCore::translate_push(const OPCODE* opcode)
{
	switch (opcode->command)
	{
	case OPCODE_PUSH_VAL:
		stack.push(opcode->lParam);
		break;
	case OPCODE_PUSH_REG:
		stack.push(get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam)));
		break;
	case OPCODE_PUSH_REGMEM:
		stack.push(get_memory_value<DWORD>(get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam))));
		break;
	default:
		break;
	}
}

void VMCore::translate_pop(const OPCODE* opcode)
{
	switch (opcode->command)
	{
	case OPCODE_POP_REG:
		set_reg_value(static_cast<REGISTER_IDS>(opcode->lParam), stack.top());
		stack.pop();
		break;
	case OPCODE_POP_REGMEM:
		set_memory_value(get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam)), stack.top());
		stack.pop();
		break;
	case OPCODE_POP_MEM:
		set_memory_value(opcode->lParam, stack.top());
		stack.pop();
		break;
	default:
		break;
	}
}

void VMCore::translate_add(const OPCODE* opcode)
{
	DWORD lVal = 0;
	DWORD rVal = 0;
	switch (opcode->command)
	{
	case OPCODE_ADD_REG_REG:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->rParam));
		set_reg_value(static_cast<REGISTER_IDS>(opcode->lParam), lVal + rVal);
		break;
	case OPCODE_ADD_REG_VAL:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = opcode->rParam;
		set_reg_value(static_cast<REGISTER_IDS>(opcode->lParam), lVal + rVal);
		break;
	case OPCODE_ADD_REG_MEM:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = get_memory_value<DWORD>(opcode->rParam);
		set_reg_value(static_cast<REGISTER_IDS>(opcode->lParam), lVal + rVal);
		break;
	case OPCODE_ADD_REGMEM_VAL:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = opcode->rParam;
		set_memory_value(get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam)), lVal + rVal);
		break;
	case OPCODE_ADD_REGMEM_REG:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->rParam));
		set_memory_value(get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam)), lVal + rVal);
		break;
	default:
		break;
	}
}

void VMCore::translate_sub(const OPCODE* opcode)
{
	DWORD lVal = 0;
	DWORD rVal = 0;
	switch (opcode->command)
	{
	case OPCODE_SUB_REG_REG:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->rParam));
		set_reg_value(static_cast<REGISTER_IDS>(opcode->lParam), lVal - rVal);
		break;
	case OPCODE_SUB_REG_VAL:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = opcode->rParam;
		set_reg_value(static_cast<REGISTER_IDS>(opcode->lParam), lVal - rVal);
		break;
	case OPCODE_SUB_REG_MEM:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = get_memory_value<DWORD>(opcode->rParam);
		set_reg_value(static_cast<REGISTER_IDS>(opcode->lParam), lVal - rVal);
		break;
	case OPCODE_SUB_REGMEM_VAL:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = opcode->rParam;
		set_memory_value(get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam)), lVal - rVal);
		break;
	case OPCODE_SUB_REGMEM_REG:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->rParam));
		set_memory_value(get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam)), lVal - rVal);
		break;
	default:
		break;
	}
}

void VMCore::translate_mul(const OPCODE* opcode)
{
	DWORD lVal = 0;
	DWORD rVal = 0;
	switch (opcode->command)
	{
	case OPCODE_MUL_REG_REG:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->rParam));
		set_reg_value(static_cast<REGISTER_IDS>(opcode->lParam), lVal * rVal);
		break;
	case OPCODE_MUL_REG_VAL:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = opcode->rParam;
		set_reg_value(static_cast<REGISTER_IDS>(opcode->lParam), lVal * rVal);
		break;
	case OPCODE_MUL_REG_MEM:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = get_memory_value<DWORD>(opcode->rParam);
		set_reg_value(static_cast<REGISTER_IDS>(opcode->lParam), lVal * rVal);
		break;
	case OPCODE_MUL_REGMEM_VAL:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = opcode->rParam;
		set_memory_value(get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam)), lVal * rVal);
		break;
	case OPCODE_MUL_REGMEM_REG:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->rParam));
		set_memory_value(get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam)), lVal * rVal);
		break;
	default:
		break;
	}
}

void VMCore::translate_xor(const OPCODE* opcode)
{
	DWORD lVal = 0;
	DWORD rVal = 0;
	switch (opcode->command)
	{
	case OPCODE_XOR_REG_REG:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->rParam));
		set_reg_value(static_cast<REGISTER_IDS>(opcode->lParam), lVal ^ rVal);
		break;
	case OPCODE_XOR_REG_VAL:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = opcode->rParam;
		set_reg_value(static_cast<REGISTER_IDS>(opcode->lParam), lVal ^ rVal);
		break;
	case OPCODE_XOR_REG_MEM:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = get_memory_value<DWORD>(opcode->rParam);
		set_reg_value(static_cast<REGISTER_IDS>(opcode->lParam), lVal ^ rVal);
		break;
	case OPCODE_XOR_REGMEM_VAL:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = opcode->rParam;
		set_memory_value(get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam)), lVal ^ rVal);
		break;
	case OPCODE_XOR_REGMEM_REG:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->rParam));
		set_memory_value(get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam)), lVal ^ rVal);
		break;
	default:
		break;
	}
}

void VMCore::translate_and(const OPCODE* opcode)
{
	DWORD lVal = 0;
	DWORD rVal = 0;
	switch (opcode->command)
	{
	case OPCODE_AND_REG_REG:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->rParam));
		set_reg_value(static_cast<REGISTER_IDS>(opcode->lParam), lVal & rVal);
		break;
	case OPCODE_AND_REG_VAL:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = opcode->rParam;
		set_reg_value(static_cast<REGISTER_IDS>(opcode->lParam), lVal & rVal);
		break;
	case OPCODE_AND_REG_MEM:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = get_memory_value<DWORD>(opcode->rParam);
		set_reg_value(static_cast<REGISTER_IDS>(opcode->lParam), lVal & rVal);
		break;
	case OPCODE_AND_REGMEM_VAL:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = opcode->rParam;
		set_memory_value(get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam)), lVal & rVal);
		break;
	case OPCODE_AND_REGMEM_REG:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->rParam));
		set_memory_value(get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam)), lVal & rVal);
		break;
	default:
		break;
	}
}

void VMCore::translate_or(const OPCODE* opcode)
{
	DWORD lVal = 0;
	DWORD rVal = 0;
	switch (opcode->command)
	{
	case OPCODE_OR_REG_REG:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->rParam));
		set_reg_value(static_cast<REGISTER_IDS>(opcode->lParam), lVal | rVal);
		break;
	case OPCODE_OR_REG_VAL:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = opcode->rParam;
		set_reg_value(static_cast<REGISTER_IDS>(opcode->lParam), lVal | rVal);
		break;
	case OPCODE_OR_REG_MEM:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = get_memory_value<DWORD>(opcode->rParam);
		set_reg_value(static_cast<REGISTER_IDS>(opcode->lParam), lVal | rVal);
		break;
	case OPCODE_OR_REGMEM_VAL:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = opcode->rParam;
		set_memory_value(get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam)), lVal | rVal);
		break;
	case OPCODE_OR_REGMEM_REG:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->rParam));
		set_memory_value(get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam)), lVal | rVal);
		break;
	default:
		break;
	}
}

void VMCore::translate_not(const OPCODE* opcode)
{
	DWORD lVal = 0;
	switch (opcode->command)
	{
	case OPCODE_NOT_REG:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		set_reg_value(static_cast<REGISTER_IDS>(opcode->lParam), ~lVal);
		break;
	case OPCODE_NOT_MEM:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		set_memory_value(get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam)), ~lVal);
		break;
	case OPCODE_NOT_REGMEM:
		lVal = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		set_memory_value(get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam)), ~lVal);
		break;
	default:
		break;
	}
}

void VMCore::translate_putchar(const OPCODE* opcode) const
{
	putchar(get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam)));
}

void VMCore::translate_getchar(const OPCODE* opcode)
{
	memorySector[cpu.memTop] = getchar();
	cpu.memTop++;
}

void VMCore::translate_interrupts(const OPCODE* opcode)
{
	switch(opcode->command)
	{
	case OPCODE_MAKE_INTERRUPT:
		cpu.interrupt = cpu.eip;
		break;
	case OPCODE_MAKE_LABEL:
		cpu.labelAdr = cpu.eip + opcode->lParam * sizeof(OPCODE);
		break;
	case OPCODE_DROP_INTERRUPT:
		cpu.interrupt = 0;
		break;
	default:
		break;
	}
}

void VMCore::translate_cmp(const OPCODE* opcode)
{
	DWORD lParam = 0;
	DWORD rParam = 0;

	switch(opcode->command)
	{
	case OPCODE_CMP_REG_REG:
		lParam = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rParam = get_reg_value(static_cast<REGISTER_IDS>(opcode->rParam));
		break;
	case OPCODE_CMP_REG_VAL:
		lParam = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rParam = opcode->rParam;
		break;
	case OPCODE_CMP_REGMEM_VAL:
		lParam = get_memory_value<DWORD>(get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam)));
		rParam = opcode->rParam;
		break;

	case OPCODE_CMP_REG_MEM:
		lParam = get_reg_value(static_cast<REGISTER_IDS>(opcode->lParam));
		rParam = get_memory_value<DWORD>(static_cast<REGISTER_IDS>(opcode->rParam));
		break;
	default:
		break;
	}
	lParam -= rParam;

	cpu.zf = (lParam == 0) ? 1 : 0;
}

void VMCore::translate_jmp(const OPCODE* opcode)
{
	switch(opcode->command)
	{
	case OPCODE_JMP_LABEL:
		cpu.eip = cpu.labelAdr;
		break;
	case OPCODE_JMP_INTERRUPT:
		cpu.eip = cpu.interrupt;
		break;
	default:
		break;
	}

}

void VMCore::translate_jnz(const OPCODE* opcode)
{
	if(cpu.zf)
		return;

	switch(opcode->command)
	{
	case OPCODE_JNZ_LABEL:
		cpu.eip = cpu.labelAdr;
		break;

	case OPCODE_JNZ_INTERRUPT:
		cpu.eip = cpu.interrupt;
		break;
	default:
		break;
	}
}

void VMCore::translate_jz(const OPCODE* opcode)
{
	if(!cpu.zf)
		return;

	switch(opcode->command)
	{
	case OPCODE_JZ_INTERRUPT:
		cpu.eip = cpu.interrupt;
		break;

	case OPCODE_JZ_LABEL:
		cpu.eip = cpu.labelAdr;
		break;
	default:
		break;
	}
}


byte* VMCore::create_program()
{
	VM_HEADER header = { 0x1337, 1024};

	OPCODE opcodes[] = 
	{
		//push "password->" string
		{OPCODE_PUSH_VAL, ('>' ^ 0x3C), 0},//>
		{OPCODE_PUSH_VAL, ('-' ^ 0x3C), 0},//-
		{OPCODE_PUSH_VAL, ('d' ^ 0x3C), 0},//d
		{OPCODE_PUSH_VAL, ('r' ^ 0x3C), 0},//r
		{OPCODE_PUSH_VAL, ('o' ^ 0x3C), 0},//o
		{OPCODE_PUSH_VAL, ('w' ^ 0x3C), 0},//w
		{OPCODE_PUSH_VAL, ('s' ^ 0x3C), 0},//s
		{OPCODE_PUSH_VAL, ('s' ^ 0x3C), 0},//s
		{OPCODE_PUSH_VAL, ('a' ^ 0x3C), 0},//a
		{OPCODE_PUSH_VAL, ('p' ^ 0x3C), 0},//p

		{OPCODE_MOV_REG_VAL, REG_EAX, 10},//string length
		{OPCODE_MOV_REG_VAL, REG_EBX, 0x3C},//xor decrypt key

		//output string
		{OPCODE_MAKE_INTERRUPT, 0, 0},			//<--
		{OPCODE_POP_REG, REG_ECX, 0},				//	|
		{OPCODE_XOR_REG_REG, REG_ECX, REG_EBX},	//	|
		{OPCODE_PUTCHAR, REG_ECX, 0},				//	|
		{OPCODE_SUB_REG_VAL, REG_EAX, 1},			//	|
		{OPCODE_CMP_REG_VAL, REG_EAX, 0},			//	|
		{OPCODE_JNZ_INTERRUPT, 0, 0},				//--|
		
		{OPCODE_DROP_INTERRUPT,0, 0},

		//push password (xored)
		{OPCODE_PUSH_VAL, ('!' ^ 0xAC), 0},//!
		{OPCODE_PUSH_VAL, ('r' ^ 0xAC), 0},//r
		{OPCODE_PUSH_VAL, ('3' ^ 0xAC), 0},//3
		{OPCODE_PUSH_VAL, ('k' ^ 0xAC), 0},//k
		{OPCODE_PUSH_VAL, ('c' ^ 0xAC), 0},//c
		{OPCODE_PUSH_VAL, ('4' ^ 0xAC), 0},//4
		{OPCODE_PUSH_VAL, ('r' ^ 0xAC), 0},//r
		{OPCODE_PUSH_VAL, ('c' ^ 0xAC), 0},//c
		{OPCODE_PUSH_VAL, ('_' ^ 0xAC), 0},//_
		{OPCODE_PUSH_VAL, ('p' ^ 0xAC), 0},//p
		{OPCODE_PUSH_VAL, ('0' ^ 0xAC), 0},//0
		{OPCODE_PUSH_VAL, ('t' ^ 0xAC), 0},//t
		{OPCODE_PUSH_VAL, ('_' ^ 0xAC), 0},//_
		{OPCODE_PUSH_VAL, ('m' ^ 0xAC), 0},//m
		{OPCODE_PUSH_VAL, ('4' ^ 0xAC), 0},//4
		{OPCODE_PUSH_VAL, ('_' ^ 0xAC), 0},//_
		{OPCODE_PUSH_VAL, ('i' ^ 0xAC), 0},//i

		//get password (password stored in memory)
		{OPCODE_MOV_REG_VAL, REG_EAX, 17},//loop password length
		{OPCODE_PUSH_REG, REG_EAX, 0},//store password length
		
		{OPCODE_MAKE_INTERRUPT, 0, 0},                //<--
		{OPCODE_GETCHAR, 0, 0},						//	|
		{OPCODE_SUB_REG_VAL, REG_EAX, 1},				//	|
		{OPCODE_CMP_REG_VAL, REG_EAX, 0},				//	|
		{OPCODE_JNZ_INTERRUPT, 0, 0},					//--|
		
		{OPCODE_MAKE_LABEL, 16, 0},//16 opcodes of check loop
		{OPCODE_DROP_INTERRUPT,0, 0},
		{OPCODE_POP_REG, REG_EAX, 0},
		{OPCODE_MOV_REG_VAL, REG_EBX, 0},
		
		{OPCODE_MAKE_INTERRUPT, 0, 0},				//<------
		{OPCODE_MOV_REG_REGMEM, REG_ECX, REG_EBX},	//		|
		{OPCODE_XOR_REG_VAL, REG_ECX, 0xAC},			//		|
		{OPCODE_POP_REG, REG_EDX, 0},					//		|
		{OPCODE_CMP_REG_REG, REG_EDX, REG_ECX},		//		|
		{OPCODE_JNZ_LABEL, 0, 0},						//---	|
		{OPCODE_ADD_REG_VAL, REG_EBX, 1},				//	|	|
		{OPCODE_SUB_REG_VAL, REG_EAX, 1},				//	|	|
		{OPCODE_CMP_REG_VAL, REG_EAX, 0},				//	|	|
		{OPCODE_JNZ_INTERRUPT, 0, 0},					//	|---|
		{OPCODE_MAKE_LABEL, 4, 0},					//	|
		{OPCODE_JMP_LABEL, 0, 0},						//	|---|
		{OPCODE_NOP, 0, 0},	//nop<---------------------	|	|
		{OPCODE_NOP, 0, 0},//nop								|
		{OPCODE_END, 0, 0},//end								|
																		//			|		
		//push end message												//			|
		{OPCODE_PUSH_VAL, ('\n' ^ 0x3B), 0},//\n	//<----------
		{OPCODE_PUSH_VAL, ('\r' ^ 0x3B), 0},//\r	
		{OPCODE_PUSH_VAL, ('}' ^ 0x3B), 0},//}	
		{OPCODE_PUSH_VAL, ('3' ^ 0x3B), 0},//3
		{OPCODE_PUSH_VAL, ('m' ^ 0x3B), 0},//m
		{OPCODE_PUSH_VAL, ('_' ^ 0x3B), 0},//_
		{OPCODE_PUSH_VAL, ('3' ^ 0x3B), 0},//3
		{OPCODE_PUSH_VAL, ('5' ^ 0x3B), 0},//5
		{OPCODE_PUSH_VAL, ('r' ^ 0x3B), 0},//r
		{OPCODE_PUSH_VAL, ('3' ^ 0x3B), 0},//3
		{OPCODE_PUSH_VAL, ('v' ^ 0x3B), 0},//v
		{OPCODE_PUSH_VAL, ('3' ^ 0x3B), 0},//3
		{OPCODE_PUSH_VAL, ('r' ^ 0x3B), 0},//r
		{OPCODE_PUSH_VAL, ('_' ^ 0x3B), 0},//_
		{OPCODE_PUSH_VAL, ('7' ^ 0x3B), 0},//7
		{OPCODE_PUSH_VAL, ('n' ^ 0x3B), 0},//n
		{OPCODE_PUSH_VAL, ('0' ^ 0x3B), 0},//0
		{OPCODE_PUSH_VAL, ('d' ^ 0x3B), 0},//d
		{OPCODE_PUSH_VAL, ('_' ^ 0x3B), 0},//_
		{OPCODE_PUSH_VAL, ('3' ^ 0x3B), 0},//3
		{OPCODE_PUSH_VAL, ('E' ^ 0x3B), 0},//s
		{OPCODE_PUSH_VAL, ('4' ^ 0x3B), 0},//4
		{OPCODE_PUSH_VAL, ('3' ^ 0x3B), 0},//3
		{OPCODE_PUSH_VAL, ('1' ^ 0x3B), 0},//1
		{OPCODE_PUSH_VAL, ('p' ^ 0x3B), 0},//p
		{OPCODE_PUSH_VAL, ('{' ^ 0x3B), 0},//{
		{OPCODE_PUSH_VAL, ('B' ^ 0x3B), 0},//B
		{OPCODE_PUSH_VAL, ('H' ^ 0x3B), 0},//H
		{OPCODE_PUSH_VAL, ('S' ^ 0x3B), 0},//S
		{OPCODE_PUSH_VAL, ('>' ^ 0x3B), 0},//>
		{OPCODE_PUSH_VAL, ('-' ^ 0x3B), 0},//-
		{OPCODE_PUSH_VAL, ('g' ^ 0x3B), 0},//g
		{OPCODE_PUSH_VAL, ('a' ^ 0x3B), 0},//a
		{OPCODE_PUSH_VAL, ('l' ^ 0x3B), 0},//l
		{OPCODE_PUSH_VAL, ('f' ^ 0x3B), 0},//f

		{ OPCODE_MOV_REG_VAL, REG_EAX, 35 },//string length
		{ OPCODE_MOV_REG_VAL, REG_EBX, 0x3B },//xor decrypt key

		//output string
		{ OPCODE_MAKE_INTERRUPT, 0, 0 },			//<--
		{ OPCODE_POP_REG, REG_ECX, 0 },			//	|
		{ OPCODE_XOR_REG_REG, REG_ECX, REG_EBX },	//	|
		{ OPCODE_PUTCHAR, REG_ECX, 0 },			//	|
		{ OPCODE_SUB_REG_VAL, REG_EAX, 1 },		//	|
		{ OPCODE_CMP_REG_VAL, REG_EAX, 0 },		//	|
		{ OPCODE_JNZ_INTERRUPT, 0, 0 },			//--|

		{ OPCODE_DROP_INTERRUPT,0, 0 },

		{ OPCODE_NOP, 0, 0 },//nop
		{ OPCODE_NOP, 0, 0 },//nop
		{ OPCODE_END, 0, 0 },//end

	};
	return nullptr;
}

template <typename T>
T VMCore::get_memory_value(const DWORD& adr)
{
	return (T)(*(memorySector + adr));
}

template <typename T>
void VMCore::set_memory_value(const DWORD& adr, const T& val)
{
	*(T*)(memorySector + adr) = val;
}

#if !NDEBUG

void VMCore::de_exec()
{
	byte* opcodes = (programSector + sizeof(VM_HEADER));
	for (unsigned i = 0; i < 1340; i += sizeof(OPCODE))
	{
		std::cout << decompile(reinterpret_cast<OPCODE*>(opcodes + i)) << std::endl;
	}
}

std::string VMCore::get_reg_name(const REGISTER_IDS& reg) const
{
	switch (reg)
	{
	case REG_EAX:
		return "eax";
	case REG_EBX:
		return "ebx";
	case REG_ECX:
		return "ecx";
	case REG_EDX:
		return "edx";
	default:
		return "";
	}
}

std::string VMCore::decompile(const OPCODE* opcode)
{
	switch (opcode->command)
	{
	case OPCODE_NOP:
		return "NOP";
	case OPCODE_END:
		return  "END";

	case OPCODE_MOV_REG_VAL:
	case OPCODE_MOV_REG_REG:
	case OPCODE_MOV_REGMEM_VAL:
	case OPCODE_MOV_REG_REGMEM:
	case OPCODE_MOV_MEM_VAL:
	case OPCODE_MOV_MEM_REG:
	case OPCODE_MOV_REG_MEM:
		return decompile_mov(opcode);
		

	case OPCODE_PUSH_VAL:
	case OPCODE_PUSH_REG:
	case OPCODE_PUSH_REGMEM:
		return decompile_push(opcode);
		

	case OPCODE_POP_REG:
	case OPCODE_POP_REGMEM:
	case OPCODE_POP_MEM:
		return decompile_pop(opcode);
		

	case OPCODE_ADD_REG_REG:
	case OPCODE_ADD_REG_VAL:
	case OPCODE_ADD_REG_MEM:
	case OPCODE_ADD_REGMEM_VAL:
	case OPCODE_ADD_REGMEM_REG:
		return decompile_add(opcode);
		

	case OPCODE_SUB_REG_REG:
	case OPCODE_SUB_REG_VAL:
	case OPCODE_SUB_REG_MEM:
	case OPCODE_SUB_REGMEM_VAL:
	case OPCODE_SUB_REGMEM_REG:
		return decompile_sub(opcode);
		

	case OPCODE_MUL_REG_REG:
	case OPCODE_MUL_REG_VAL:
	case OPCODE_MUL_REG_MEM:
	case OPCODE_MUL_REGMEM_VAL:
	case OPCODE_MUL_REGMEM_REG:
		return decompile_mul(opcode);
		

	case OPCODE_XOR_REG_REG:
	case OPCODE_XOR_REG_VAL:
	case OPCODE_XOR_REG_MEM:
	case OPCODE_XOR_REGMEM_VAL:
	case OPCODE_XOR_REGMEM_REG:
		return decompile_xor(opcode);
		

	case OPCODE_AND_REG_REG:
	case OPCODE_AND_REG_VAL:
	case OPCODE_AND_REG_MEM:
	case OPCODE_AND_REGMEM_VAL:
	case OPCODE_AND_REGMEM_REG:
		return decompile_and(opcode);
		

	case OPCODE_NOT_REG:
	case OPCODE_NOT_REGMEM:
	case OPCODE_NOT_MEM:
		return decompile_not(opcode);
		

	case OPCODE_PUTCHAR:
		return decompile_putchar(opcode);
		

	case OPCODE_GETCHAR:
		return decompile_getchar(opcode);
		

	case OPCODE_MAKE_INTERRUPT:
	case OPCODE_DROP_INTERRUPT:
	case OPCODE_MAKE_LABEL:
		return decompile_interrupts(opcode);
		

	case OPCODE_CMP_REG_REG:
	case OPCODE_CMP_REG_VAL:
	case OPCODE_CMP_REGMEM_VAL:
	case OPCODE_CMP_REG_MEM:
		return decompile_cmp(opcode);
		

	case OPCODE_JMP_INTERRUPT:
	case OPCODE_JMP_LABEL:
		return decompile_jmp(opcode);
		

	case OPCODE_JNZ_LABEL:
	case OPCODE_JNZ_INTERRUPT:
		return decompile_jnz(opcode);
		

	case OPCODE_JZ_INTERRUPT:
	case OPCODE_JZ_LABEL:
		return decompile_jz(opcode);
	default:
		return  "UNKNOWN";
	}
}

std::string VMCore::decompile_mov(const OPCODE* opcode)
{
	switch (opcode->command)
	{
	case OPCODE_MOV_REG_VAL:
		return "mov " + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + ", " + std::to_string(opcode->rParam);
	case OPCODE_MOV_REG_REG:
		return "mov " + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + ", " + get_reg_name(static_cast<REGISTER_IDS>(opcode->rParam));
	case OPCODE_MOV_REGMEM_VAL:
		return "mov [" + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + "], " + std::to_string(opcode->rParam);
	case OPCODE_MOV_REG_REGMEM:
		return "mov " + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + ", [" + get_reg_name(static_cast<REGISTER_IDS>(opcode->rParam)) + "]";
	case OPCODE_MOV_MEM_VAL:
		return "mov [" + std::to_string(opcode->lParam) + "], " + std::to_string(opcode->rParam);
	case OPCODE_MOV_MEM_REG:
		return "mov [" + std::to_string(opcode->lParam) + "], " + get_reg_name(static_cast<REGISTER_IDS>(opcode->rParam));
	case OPCODE_MOV_REG_MEM:
		return "mov " + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + ", [" + std::to_string(opcode->rParam) + "]";
	default:
		return "\r\n";
	}
}

std::string VMCore::decompile_push(const OPCODE* opcode)
{
	switch (opcode->command)
	{
	case OPCODE_PUSH_VAL:
		return "push " + std::to_string(opcode->lParam);
		
	case OPCODE_PUSH_REG:
			return "push " + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam));

	case OPCODE_PUSH_REGMEM:
		return "push [" + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + "]";
	default:
		return  "";
	}
}

std::string VMCore::decompile_pop(const OPCODE* opcode)
{
	switch (opcode->command)
	{
	case OPCODE_POP_MEM:
		return "pop [" + std::to_string(opcode->lParam) + "]";

	case OPCODE_POP_REG:
		return "pop " + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam));

	case OPCODE_PUSH_REGMEM:
		return "pop [" + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + "]";
	default:
		return  "";
	}
}

std::string VMCore::decompile_add(const OPCODE* opcode)
{
	switch (opcode->command)
	{
	case OPCODE_ADD_REG_VAL:
		return "add " + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + ", " + std::to_string(opcode->rParam);
	case OPCODE_ADD_REG_REG:
		return "add " + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + ", " + get_reg_name(static_cast<REGISTER_IDS>(opcode->rParam));
	case OPCODE_ADD_REGMEM_VAL:
		return "add [" + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + "], " + std::to_string(opcode->rParam);
	case OPCODE_ADD_REG_MEM:
		return "add " + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + ", [" + get_reg_name(static_cast<REGISTER_IDS>(opcode->rParam)) + "]";
	case OPCODE_ADD_REGMEM_REG:
		return "add [" + std::to_string(opcode->lParam) + "], " + get_reg_name(static_cast<REGISTER_IDS>(opcode->rParam));
	default:
		return "\r\n";
	}
}

std::string VMCore::decompile_sub(const OPCODE* opcode)
{
	switch (opcode->command)
	{
	case OPCODE_SUB_REG_VAL:
		return "sub " + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + ", " + std::to_string(opcode->rParam);
	case OPCODE_SUB_REG_REG:
		return "sub " + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + ", " + get_reg_name(static_cast<REGISTER_IDS>(opcode->rParam));
	case OPCODE_SUB_REGMEM_VAL:
		return "sub [" + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + "], " + std::to_string(opcode->rParam);
	case OPCODE_SUB_REG_MEM:
		return "sub " + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + ", [" + get_reg_name(static_cast<REGISTER_IDS>(opcode->rParam)) + "]";
	case OPCODE_SUB_REGMEM_REG:
		return "sub [" + std::to_string(opcode->lParam) + "], " + get_reg_name(static_cast<REGISTER_IDS>(opcode->rParam));
	default:
		return "\r\n";
	}
}

std::string VMCore::decompile_mul(const OPCODE* opcode)
{
	switch (opcode->command)
	{
	case OPCODE_MUL_REG_VAL:
		return "mul " + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + ", " + std::to_string(opcode->rParam);
	case OPCODE_MUL_REG_REG:
		return "mul " + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + ", " + get_reg_name(static_cast<REGISTER_IDS>(opcode->rParam));
	case OPCODE_MUL_REGMEM_VAL:
		return "mul [" + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + "], " + std::to_string(opcode->rParam);
	case OPCODE_MUL_REG_MEM:
		return "mul " + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + ", [" + get_reg_name(static_cast<REGISTER_IDS>(opcode->rParam)) + "]";
	case OPCODE_MUL_REGMEM_REG:
		return "mul [" + std::to_string(opcode->lParam) + "], " + get_reg_name(static_cast<REGISTER_IDS>(opcode->rParam));
	default:
		return "\r\n";
	}
}

std::string VMCore::decompile_xor(const OPCODE* opcode)
{
	switch (opcode->command)
	{
	case OPCODE_XOR_REG_VAL:
		return "xor " + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + ", " + std::to_string(opcode->rParam);
	case OPCODE_XOR_REG_REG:
		return "xor " + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + ", " + get_reg_name(static_cast<REGISTER_IDS>(opcode->rParam));
	case OPCODE_XOR_REGMEM_VAL:
		return "xor [" + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + "], " + std::to_string(opcode->rParam);
	case OPCODE_XOR_REG_MEM:
		return "xor " + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + ", [" + get_reg_name(static_cast<REGISTER_IDS>(opcode->rParam)) + "]";
	case OPCODE_XOR_REGMEM_REG:
		return "xor [" + std::to_string(opcode->lParam) + "], " + get_reg_name(static_cast<REGISTER_IDS>(opcode->rParam));
	default:
		return "\r\n";
	}
}

std::string VMCore::decompile_and(const OPCODE* opcode)
{
	return "\r\n";
}

std::string VMCore::decompile_or(const OPCODE* opcode)
{
	return "\r\n";
}

std::string VMCore::decompile_not(const OPCODE* opcode)
{
	return "\r\n";
}

std::string VMCore::decompile_putchar(const OPCODE* opcode) const
{
	return "putchar " + get_reg_name((REGISTER_IDS)opcode->lParam);
}

std::string VMCore::decompile_getchar(const OPCODE* opcode)
{
	return "getchar";
}

std::string VMCore::decompile_interrupts(const OPCODE* opcode)
{
	switch (opcode->command)
	{
	case OPCODE_MAKE_INTERRUPT:
		return "store eip";
	case OPCODE_MAKE_LABEL:
		return "label " + std::to_string(opcode->lParam);
	case OPCODE_DROP_INTERRUPT:
		return "drop eip";
	default:
		return "";
	}
}

std::string VMCore::decompile_cmp(const OPCODE* opcode)
{
	switch (opcode->command)
	{
	case OPCODE_CMP_REG_REG:
		return "cmp " + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + ", " + get_reg_name(static_cast<REGISTER_IDS>(opcode->rParam));
	case OPCODE_CMP_REG_VAL:
		return "cmp " + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + ", " + std::to_string(opcode->rParam);
	case OPCODE_CMP_REGMEM_VAL:
		return "cmp [" + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + "], " + std::to_string(opcode->rParam);
	case OPCODE_CMP_REG_MEM:
		return "cmp " + get_reg_name(static_cast<REGISTER_IDS>(opcode->lParam)) + ", [" + std::to_string(opcode->rParam) + "]";
	default:
		return "";
	}
}

std::string VMCore::decompile_jmp(const OPCODE* opcode)
{
	switch (opcode->command)
	{
	case OPCODE_JMP_LABEL:
		return "jmp label";
	case OPCODE_JMP_INTERRUPT:
		return "jmp stored_eip";
	default:
		return "";
	}
}

std::string VMCore::decompile_jnz(const OPCODE* opcode)
{
	switch (opcode->command)
	{
	case OPCODE_JNZ_LABEL:
		return "jnz label";
	case OPCODE_JNZ_INTERRUPT:
		return "jmp stored_eip";
	default:
		return "";
	}
}

std::string VMCore::decompile_jz(const OPCODE* opcode)
{
	switch (opcode->command)
	{
	case OPCODE_JZ_LABEL:
		return "jz label";
	case OPCODE_JZ_INTERRUPT:
		return "jz stored_eip";
	default:
		return "";
	}
}

#endif
