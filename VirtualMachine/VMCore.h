#pragma once
#include <Windows.h>
#include <stack>

class VMCore
{
public:
	VMCore();

	void load(byte* raw, DWORD rawSize);
	void exec();
	byte* create_program();
private:
	enum OPCODE_NAMES : BYTE
	{
		OPCODE_MOV_REG_VAL = 0x0,
		OPCODE_MOV_REG_REG,
		OPCODE_MOV_REG_MEM,
		OPCODE_MOV_REGMEM_VAL,
		OPCODE_MOV_REG_REGMEM,
		OPCODE_MOV_MEM_VAL,
		OPCODE_MOV_MEM_REG,

		OPCODE_PUSH_VAL,
		OPCODE_PUSH_REG,
		OPCODE_PUSH_REGMEM,

		OPCODE_POP_REG,
		OPCODE_POP_REGMEM,
		OPCODE_POP_MEM,

		OPCODE_ADD_REG_REG,
		OPCODE_ADD_REG_VAL,
		OPCODE_ADD_REG_MEM,
		OPCODE_ADD_REGMEM_VAL,
		OPCODE_ADD_REGMEM_REG,

		OPCODE_SUB_REG_REG,
		OPCODE_SUB_REG_VAL,
		OPCODE_SUB_REG_MEM,
		OPCODE_SUB_REGMEM_VAL,
		OPCODE_SUB_REGMEM_REG,

		OPCODE_MUL_REG_REG,
		OPCODE_MUL_REG_VAL,
		OPCODE_MUL_REG_MEM,
		OPCODE_MUL_REGMEM_VAL,
		OPCODE_MUL_REGMEM_REG,

		OPCODE_XOR_REG_REG,
		OPCODE_XOR_REG_VAL,
		OPCODE_XOR_REG_MEM,
		OPCODE_XOR_REGMEM_VAL,
		OPCODE_XOR_REGMEM_REG,

		OPCODE_AND_REG_REG,
		OPCODE_AND_REG_VAL,
		OPCODE_AND_REG_MEM,
		OPCODE_AND_REGMEM_VAL,
		OPCODE_AND_REGMEM_REG,

		OPCODE_OR_REG_REG,
		OPCODE_OR_REG_VAL,
		OPCODE_OR_REG_MEM,
		OPCODE_OR_REGMEM_VAL,
		OPCODE_OR_REGMEM_REG,

		OPCODE_NOT_REG,
		OPCODE_NOT_REGMEM,
		OPCODE_NOT_MEM,

		OPCODE_CMP_REG_REG,
		OPCODE_CMP_REG_VAL,
		OPCODE_CMP_REG_MEM,
		OPCODE_CMP_REGMEM_VAL,
		OPCODE_CMP_REGMEM_REG,

		OPCODE_MAKE_INTERRUPT,
		OPCODE_MAKE_LABEL,
		OPCODE_DROP_INTERRUPT,

		OPCODE_JMP_INTERRUPT,
		OPCODE_JMP_LABEL,

		OPCODE_JZ_INTERRUPT,
		OPCODE_JZ_LABEL,

		OPCODE_JNZ_INTERRUPT,
		OPCODE_JNZ_LABEL,


		OPCODE_PUTCHAR,
		OPCODE_GETCHAR,

		OPCODE_NOP,
		OPCODE_END
	};

	enum OPCODE_TYPES : BYTE
	{
		REGISTER_TYPE = 0x0,
		VALUE_TYPE,
		MEMORY_TYPE
	};

	enum REGISTER_IDS : BYTE
	{
		REG_EAX = 0x0,
		REG_EBX,
		REG_ECX,
		REG_EDX,
	};

	struct Processor
	{
		DWORD eax;
		DWORD ebx;
		DWORD ecx;
		DWORD edx;

		DWORD eip;
		DWORD interrupt;
		DWORD labelAdr;

		DWORD memTop;

		BYTE zf;

	};

	struct VM_HEADER
	{
		DWORD magic;
		DWORD memoryAlloc;
	};

	struct OPCODE
	{
		OPCODE_NAMES command;
		DWORD lParam;
		DWORD rParam;
	};


	VM_HEADER* pHeader;
	std::stack<DWORD> stack;

	byte* programSector;
	byte* memorySector;

	Processor cpu{};


	void  set_reg_value(const REGISTER_IDS& reg, const DWORD& val);
	DWORD get_reg_value(const REGISTER_IDS& reg) const;

	template <typename T>
	T get_memory_value(const DWORD& adr);

	template<typename T>
	void set_memory_value(const DWORD& adr, const T& val);

	void translate(const OPCODE* opcode);

	void translate_mov(const OPCODE* opcode);
	void translate_push(const OPCODE* opcode);
	void translate_pop(const OPCODE* opcode);
	void translate_add(const OPCODE* opcode);
	void translate_sub(const OPCODE* opcode);
	void translate_mul(const OPCODE* opcode);
	void translate_xor(const OPCODE* opcode);
	void translate_and(const OPCODE* opcode);
	void translate_or(const OPCODE* opcode);
	void translate_not(const OPCODE* opcode);

	void translate_putchar(const OPCODE* opcode) const;
	void translate_getchar(const OPCODE* opcode);

	void translate_interrupts(const OPCODE* opcode);

	void translate_cmp(const OPCODE* opcode);
	void translate_jmp(const OPCODE* opcode);
	void translate_jnz(const OPCODE* opcode);
	void translate_jz(const OPCODE* opcode);

#if !NDEBUG
public:
	void de_exec();

private:
	std::string get_reg_name(const REGISTER_IDS& reg) const;

	std::string decompile(const OPCODE* opcode);
	std::string decompile_mov(const OPCODE* opcode);
	std::string decompile_push(const OPCODE* opcode);
	std::string decompile_pop(const OPCODE* opcode);
	std::string decompile_add(const OPCODE* opcode);
	std::string decompile_sub(const OPCODE* opcode);
	std::string decompile_mul(const OPCODE* opcode);
	std::string decompile_xor(const OPCODE* opcode);
	std::string decompile_and(const OPCODE* opcode);
	std::string decompile_or(const OPCODE* opcode);
	std::string decompile_not(const OPCODE* opcode);

	std::string decompile_putchar(const OPCODE* opcode) const;
	std::string decompile_getchar(const OPCODE* opcode);

	std::string decompile_interrupts(const OPCODE* opcode);

	std::string decompile_cmp(const OPCODE* opcode);
	std::string decompile_jmp(const OPCODE* opcode);
	std::string decompile_jnz(const OPCODE* opcode);
	std::string decompile_jz(const OPCODE* opcode);
#endif

};