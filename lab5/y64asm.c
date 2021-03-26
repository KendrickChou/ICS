#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "y64asm.h"

line_t *line_head = NULL;
line_t *line_tail = NULL;
int lineno = 0;

#define err_print(_s, _a...)            \
    do                                  \
    {                                   \
        if (lineno < 0)                 \
            fprintf(stderr, "[--]: "_s  \
                            "\n",       \
                    ##_a);              \
        else                            \
            fprintf(stderr, "[L%d]: "_s \
                            "\n",       \
                    lineno, ##_a);      \
    } while (0);

int64_t vmaddr = 0; /* vm addr */

/* register table */
const reg_t reg_table[REG_NONE] = {
    {"%rax", REG_RAX, 4},
    {"%rcx", REG_RCX, 4},
    {"%rdx", REG_RDX, 4},
    {"%rbx", REG_RBX, 4},
    {"%rsp", REG_RSP, 4},
    {"%rbp", REG_RBP, 4},
    {"%rsi", REG_RSI, 4},
    {"%rdi", REG_RDI, 4},
    {"%r8", REG_R8, 3},
    {"%r9", REG_R9, 3},
    {"%r10", REG_R10, 4},
    {"%r11", REG_R11, 4},
    {"%r12", REG_R12, 4},
    {"%r13", REG_R13, 4},
    {"%r14", REG_R14, 4}};
const reg_t *find_register(char *name)
{
    int i;
    for (i = 0; i < REG_NONE; i++)
        if (!strncmp(name, reg_table[i].name, reg_table[i].namelen))
            return &reg_table[i];
    return NULL;
}

/* instruction set */
instr_t instr_set[] = {
    {"nop", 3, HPACK(I_NOP, F_NONE), 1},
    {"halt", 4, HPACK(I_HALT, F_NONE), 1},
    {"rrmovq", 6, HPACK(I_RRMOVQ, F_NONE), 2},
    {"cmovle", 6, HPACK(I_RRMOVQ, C_LE), 2},
    {"cmovl", 5, HPACK(I_RRMOVQ, C_L), 2},
    {"cmove", 5, HPACK(I_RRMOVQ, C_E), 2},
    {"cmovne", 6, HPACK(I_RRMOVQ, C_NE), 2},
    {"cmovge", 6, HPACK(I_RRMOVQ, C_GE), 2},
    {"cmovg", 5, HPACK(I_RRMOVQ, C_G), 2},
    {"irmovq", 6, HPACK(I_IRMOVQ, F_NONE), 10},
    {"rmmovq", 6, HPACK(I_RMMOVQ, F_NONE), 10},
    {"mrmovq", 6, HPACK(I_MRMOVQ, F_NONE), 10},
    {"addq", 4, HPACK(I_ALU, A_ADD), 2},
    {"subq", 4, HPACK(I_ALU, A_SUB), 2},
    {"andq", 4, HPACK(I_ALU, A_AND), 2},
    {"xorq", 4, HPACK(I_ALU, A_XOR), 2},
    {"jmp", 3, HPACK(I_JMP, C_YES), 9},
    {"jle", 3, HPACK(I_JMP, C_LE), 9},
    {"jl", 2, HPACK(I_JMP, C_L), 9},
    {"je", 2, HPACK(I_JMP, C_E), 9},
    {"jne", 3, HPACK(I_JMP, C_NE), 9},
    {"jge", 3, HPACK(I_JMP, C_GE), 9},
    {"jg", 2, HPACK(I_JMP, C_G), 9},
    {"call", 4, HPACK(I_CALL, F_NONE), 9},
    {"ret", 3, HPACK(I_RET, F_NONE), 1},
    {"pushq", 5, HPACK(I_PUSHQ, F_NONE), 2},
    {"popq", 4, HPACK(I_POPQ, F_NONE), 2},
    {".byte", 5, HPACK(I_DIRECTIVE, D_DATA), 1},
    {".word", 5, HPACK(I_DIRECTIVE, D_DATA), 2},
    {".long", 5, HPACK(I_DIRECTIVE, D_DATA), 4},
    {".quad", 5, HPACK(I_DIRECTIVE, D_DATA), 8},
    {".pos", 4, HPACK(I_DIRECTIVE, D_POS), 0},
    {".align", 6, HPACK(I_DIRECTIVE, D_ALIGN), 0},
    {NULL, 1, 0, 0} //end
};

instr_t *find_instr(char *name)
{
    int i;
    for (i = 0; instr_set[i].name; i++)
        if (strncmp(instr_set[i].name, name, instr_set[i].len) == 0)
            return &instr_set[i];
    return NULL;
}

/* symbol table (don't forget to init and finit it) */
symbol_t *symtab = NULL;

/*
 * find_symbol: scan table to find the symbol
 * args
 *     name: the name of symbol
 *
 * return
 *     symbol_t: the 'name' symbol
 *     NULL: not exist
 */
symbol_t *find_symbol(char *name)
{
    symbol_t *iter = symtab->next;
    while (iter)
    {
        if (!strcmp(iter->name,name))
            return iter;
        iter = iter->next;
    }
    return NULL;
}

/*
 * add_symbol: add a new symbol to the symbol table
 * args
 *     name: the name of symbol
 *
 * return
 *     0: success
 *     -1: error, the symbol has exist
 */
int add_symbol(char *name)
{
    symbol_t *newSymbol;
    if (newSymbol = find_symbol(name))
    {
        return -1;
    }
     newSymbol = (symbol_t *)malloc(sizeof(symbol_t));
    newSymbol->name = name;
    newSymbol->next = symtab->next;
    symtab->next = newSymbol;
    return 0;
    /* check duplicate */

    /* create new symbol_t (don't forget to free it)*/

    /* add the new symbol_t to symbol table */
}

/* relocation table (don't forget to init and finit it) */
reloc_t *reltab = NULL;

/*
 * add_reloc: add a new relocation to the relocation table
 * args
 *     name: the name of symbol
 */
void add_reloc(char *name, bin_t *bin)
{
    reloc_t *newReloc;
    newReloc = malloc(sizeof(reloc_t));
    newReloc->name = name;
    newReloc->y64bin = bin;
    newReloc->next = reltab->next;
    reltab->next = newReloc;
    /* create new reloc_t (don't forget to free it)*/

    /* add the new reloc_t to relocation table */
}

/* macro for parsing y64 assembly code */
#define IS_DIGIT(s) ((*(s) >= '0' && *(s) <= '9') || *(s) == '-' || *(s) == '+')
#define IS_LETTER(s) ((*(s) >= 'a' && *(s) <= 'z') || (*(s) >= 'A' && *(s) <= 'Z'))
#define IS_COMMENT(s) (*(s) == '#')
#define IS_REG(s) (*(s) == '%')
#define IS_IMM(s) (*(s) == '$')

#define IS_BLANK(s) (*(s) == ' ' || *(s) == '\t')
#define IS_END(s) (*(s) == '\0')

#define SKIP_BLANK(s)                     \
    do                                    \
    {                                     \
        while (!IS_END(s) && IS_BLANK(s)) \
            (s)++;                        \
    } while (0);

/* return value from different parse_xxx function */
typedef enum
{
    PARSE_ERR = -1,
    PARSE_REG,
    PARSE_DIGIT,
    PARSE_SYMBOL,
    PARSE_MEM,
    PARSE_DELIM,
    PARSE_INSTR,
    PARSE_LABEL
} parse_t;

/*
 * parse_instr: parse an expected data token (e.g., 'rrmovq')
 * args
 *     ptr: point to the start of string
 *     inst: point to the inst_t within instr_set
 *
 * return
 *     PARSE_INSTR: success, move 'ptr' to the first char after token,
 *                            and store the pointer of the instruction to 'inst'
 *     PARSE_ERR: error, the value of 'ptr' and 'inst' are undefined
 */
parse_t parse_instr(char **ptr, instr_t **inst)
{
    SKIP_BLANK(*ptr);
    /* skip the blank */

    /* find_instr and check end */
    if (!IS_END(*ptr))
    {
        *inst = find_instr(*ptr);
        if (*inst == NULL)
            return PARSE_ERR;
        *ptr += (*inst)->len;
        return PARSE_INSTR;
    }
    return PARSE_ERR;
    /* set 'ptr' and 'inst' */
}

/*
 * parse_delim: parse an expected delimiter token (e.g., ',')
 * args
 *     ptr: point to the start of string
 *
 * return
 *     PARSE_DELIM: success, move 'ptr' to the first char after token
 *     PARSE_ERR: error, the value of 'ptr' and 'delim' are undefined
 */
parse_t parse_delim(char **ptr, char delim)
{
    SKIP_BLANK(*ptr);
    if (**ptr == delim)
    {
        ++(*ptr);
        return PARSE_DELIM;
    }
    /* skip the blank and check */

    /* set 'ptr' */
    return PARSE_ERR;
}

/*
 * parse_reg: parse an expected register token (e.g., '%rax')
 * args
 *     ptr: point to the start of string
 *     regid: point to the regid of register
 *
 * return
 *     PARSE_REG: success, move 'ptr' to the first char after token, 
 *                         and store the regid to 'regid'
 *     PARSE_ERR: error, the value of 'ptr' and 'regid' are undefined
 */

/*regid 必须malloc*/
parse_t parse_reg(char **ptr, regid_t *regid)
{
    SKIP_BLANK(*ptr);
    reg_t *REG;
    if (!IS_REG(*ptr))
        return PARSE_ERR;
    REG = find_register(*ptr);
    if (REG == NULL)
        return PARSE_ERR;
    *regid = REG->id;
    *ptr += REG->namelen;

    return PARSE_REG;
    /* skip the blank and check */

    /* find register */

    /* set 'ptr' and 'regid' */
}

/*
 * parse_symbol: parse an expected symbol token (e.g., 'Main')
 * args
 *     ptr: point to the start of string
 *     name: point to the name of symbol (should be allocated in this function)
 *
 * return
 *     PARSE_SYMBOL: success, move 'ptr' to the first char after token,
 *                               and allocate and store name to 'name'
 *     PARSE_ERR: error, the value of 'ptr' and 'name' are undefined
 */

//name 必须初始化
parse_t parse_symbol(char **ptr, char **name)
{
    SKIP_BLANK(*ptr);
    /* skip the blank and check */

    char *iter = *ptr;
    int len = 0;
    if (IS_LETTER(*ptr))
    {
        while (!IS_BLANK(iter) && !IS_END(iter) && *iter != ',')
        {
            ++len;
            ++iter;
        }
        char *Sym = malloc(sizeof(char) * (len + 1));
        strncpy(Sym, *ptr, len);
        *(Sym + len) = '\0';
        *name = Sym;
        *ptr += len;
        return PARSE_SYMBOL;
    }
    /* allocate name and copy to it */

    /* set 'ptr' and 'name' */

    return PARSE_ERR;
}

/*
 * parse_digit: parse an expected digit token (e.g., '0x100')
 * args
 *     ptr: point to the start of string
 *     value: point to the value of digit
 *
 * return
 *     PARSE_DIGIT: success, move 'ptr' to the first char after token
 *                            and store the value of digit to 'value'
 *     PARSE_ERR: error, the value of 'ptr' and 'value' are undefined
 */
parse_t parse_digit(char **ptr, long *value)
{
    SKIP_BLANK(*ptr);

    if (IS_DIGIT(*ptr))
    {
        char *ePtr;
        *value = strtoul(*ptr, &ePtr, 0);
        *ptr = ePtr;
        return PARSE_DIGIT;
    }
    /* skip the blank and check */

    /* calculate the digit, (NOTE: see strtoll()) */

    /* set 'ptr' and 'value' */

    return PARSE_ERR;
}

/*
 * parse_imm: parse an expected immediate token (e.g., '$0x100' or 'STACK')
 * args
 *     ptr: point to the start of string
 *     name: point to the name of symbol (should be allocated in this function)
 *     value: point to the value of digit
 *
 * return
 *     PARSE_DIGIT: success, the immediate token is a digit,
 *                            move 'ptr' to the first char after token,
 *                            and store the value of digit to 'value'
 *     PARSE_SYMBOL: success, the immediate token is a symbol,
 *                            move 'ptr' to the first char after token,
 *                            and allocate and store name to 'name' 
 *     PARSE_ERR: error, the value of 'ptr', 'name' and 'value' are undefined
 */
parse_t parse_imm(char **ptr, char **name, long *value)
{
    SKIP_BLANK(*ptr);
    /* skip the blank and check */

    if (IS_IMM(*ptr))
    {
        ++(*ptr);
        return parse_digit(ptr, value);
    }
    /* if IS_IMM, then parse the digit */

    if (IS_LETTER(*ptr))
    {
        return parse_symbol(ptr, name);
    }
    /* if IS_LETTER, then parse the symbol */

    /* set 'ptr' and 'name' or 'value' */

    return PARSE_ERR;
}

/*
 * parse_mem: parse an expected memory token (e.g., '8(%rbp)')
 * args
 *     ptr: point to the start of string
 *     value: point to the value of digit
 *     regid: point to the regid of register
 *
 * return
 *     PARSE_MEM: success, move 'ptr' to the first char after token,
 *                          and store the value of digit to 'value',
 *                          and store the regid to 'regid'
 *     PARSE_ERR: error, the value of 'ptr', 'value' and 'regid' are undefined
 */
parse_t parse_mem(char **ptr, long *value, regid_t *regid)
{
    SKIP_BLANK(*ptr);
    /* skip the blank and check */
    if (IS_DIGIT(*ptr))
    {
        if (parse_digit(ptr, value) == PARSE_ERR ||
        parse_delim(ptr, '(') == PARSE_ERR ||
        parse_reg(ptr, regid) == PARSE_ERR ||
        parse_delim(ptr, ')') == PARSE_ERR
        ){
            return PARSE_ERR;
        }
        return PARSE_MEM;
    }
    if (parse_delim(ptr, '(') != PARSE_ERR &&
        parse_reg(ptr, regid) != PARSE_ERR &&
        parse_delim(ptr, ')') != PARSE_ERR)
    {
        return PARSE_MEM;
    }
    /* calculate the digit and register, (ex: (%rbp) or 8(%rbp)) */

    /* set 'ptr', 'value' and 'regid' */

    return PARSE_ERR;
}

/*
 * parse_data: parse an expected data token (e.g., '0x100' or 'array')
 * args
 *     ptr: point to the start of string
 *     name: point to the name of symbol (should be allocated in this function)
 *     value: point to the value of digit
 *
 * return
 *     PARSE_DIGIT: success, data token is a digit,
 *                            and move 'ptr' to the first char after token,
 *                            and store the value of digit to 'value'
 *     PARSE_SYMBOL: success, data token is a symbol,
 *                            and move 'ptr' to the first char after token,
 *                            and allocate and store name to 'name' 
 *     PARSE_ERR: error, the value of 'ptr', 'name' and 'value' are undefined
 */
parse_t parse_data(char **ptr, char **name, long *value)
{
    SKIP_BLANK(*ptr);
    /* skip the blank and check */

    if (IS_DIGIT(*ptr))
    {
        return parse_digit(ptr, value);
    }
    /* if IS_DIGIT, then parse the digit */
    if (IS_LETTER(*ptr))
    {
        return parse_symbol(ptr, name);
    }
    /* if IS_LETTER, then parse the symbol */

    /* set 'ptr', 'name' and 'value' */

    return PARSE_ERR;
}

/*
 * parse_label: parse an expected label token (e.g., 'Loop:')
 * args
 *     ptr: point to the start of string
 *     name: point to the name of symbol (should be allocated in this function)
 *
 * return
 *     PARSE_LABEL: success, move 'ptr' to the first char after token
 *                            and allocate and store name to 'name'
 *     PARSE_ERR: error, the value of 'ptr' is undefined
 */
parse_t parse_label(char **ptr, char **name)
{
    //标号后面一定有“ : "嘛？
    SKIP_BLANK(*ptr);
    char *iter = *ptr;
    int len = 0;
    if (IS_LETTER(*ptr))
    {
        while (IS_LETTER(iter) || IS_DIGIT(iter))
        {
            ++len;
            ++iter;
        }
        if(*iter == ':'){
            char *Sym = malloc(sizeof(char) * (len + 1));
            strncpy(Sym, *ptr, len);
            *(Sym + len) = '\0';
            *name = Sym;
            *ptr = ++iter;
            return PARSE_LABEL;
        }
    }
    /* set 'ptr' and 'name' */
    /* allocate name and copy to it */

    /* set 'ptr' and 'name' */

    return PARSE_ERR;
}

/*
 * parse_line: parse a line of y64 code (e.g., 'Loop: mrmovq (%rcx), %rsi')
 * (you could combine above parse_xxx functions to do it)
 * args
 *     line: point to a line_t data with a line of y64 assembly code
 *
 * return
 *     PARSE_XXX: success, fill line_t with assembled y64 code
 *     PARSE_ERR: error, try to print err information (e.g., instr type and line number)
 */
type_t parse_line(line_t *line)
{
    /* when finish parse an instruction or lable, we still need to continue check 
* e.g., 
*  Loop: mrmovl (%rbp), %rcx
*           call SUM  #invoke SUM function */

    /* skip blank and check IS_END */

    /* is a comment ? */

    /* is a label ? */

    /* is an instruction ? */

    /* set type and y64bin */

    /* update vmaddr */

    /* parse the rest of instruction according to the itype */
    char *Text = line->y64asm;

    SKIP_BLANK(Text);

    if (IS_END(Text) || IS_COMMENT(Text))
        return TYPE_COMM;

    char *label = NULL;
    if (parse_label(&Text, &label) == PARSE_LABEL)
    {
        if (add_symbol(label))
        {
            err_print("Dup symbol:%s",label);
            line->type = TYPE_ERR;
            return TYPE_ERR;
        }
        symbol_t *sym = find_symbol(label);
        sym->addr = vmaddr;
        line->type = TYPE_INS;
        line->y64bin.addr = vmaddr;
        line->y64bin.bytes = 0;
        SKIP_BLANK(Text);
        if (IS_END(Text) || IS_COMMENT(Text))
            return line->type;
    }

    SKIP_BLANK(Text);
    if (IS_COMMENT(Text) || IS_END(Text))
    {
        line->type = TYPE_INS;
    }

    instr_t *INS;
    INS = (instr_t *)malloc(sizeof(instr_t));
    if (parse_instr(&Text, &INS) == PARSE_ERR)
    {
        line->type = TYPE_ERR;
        return TYPE_ERR;
    }
        line->y64bin.addr = vmaddr;
        line->y64bin.bytes = INS->bytes;
        line->y64bin.codes[0] = INS->code;
        line->type = TYPE_INS;

        vmaddr += INS->bytes;
        itype_t icode = HIGH(INS->code);

        long dig;
        regid_t rA, rB;
        char *name;
        switch (icode)
        {
        case I_NOP:
        case I_RET:
        case I_HALT:
        {
            break;
        }
        case I_ALU:
        case I_RRMOVQ:
        {
            if (parse_reg(&Text, &rA) == PARSE_ERR)
            {
                err_print("Invalid REG");
                return TYPE_ERR;
            }
            if (parse_delim(&Text, ',') == PARSE_ERR)
            {
                err_print("Invalid ','");
                return TYPE_ERR;
            }
            if (parse_reg(&Text, &rB) == PARSE_ERR)
            {
                err_print("Invalid REG");
                return TYPE_ERR;
            }
            line->y64bin.codes[1] = HPACK(rA, rB);
            break;
        }
        case I_IRMOVQ:
        {
            parse_t immType = parse_imm(&Text, &name, &dig);
            if (immType == PARSE_ERR)
            {
                err_print("Invalid Immediate");
                return TYPE_ERR;
            }
            if (parse_delim(&Text, ',') == PARSE_ERR)
            {
                err_print("Invalid ','");
                return TYPE_ERR;
            }
            if (parse_reg(&Text, &rB) == PARSE_ERR)
            {
                err_print("Invalid REG");
                return TYPE_ERR;
            }
            line->y64bin.codes[1] = HPACK(REG_NONE, rB);
            if (immType == PARSE_DIGIT)
            {
                for (int i = 0; i < 8; ++i)
                {
                    line->y64bin.codes[i + 2] = ((dig >> 8 * i) & 0xFF);
                }
            }
            else
            {
                add_reloc(name, &line->y64bin);
            }
            break;
        }
        case I_RMMOVQ:
        {
            if (parse_reg(&Text, &rA) == PARSE_ERR)
            {
                err_print("Invalid REG");
                return TYPE_ERR;
            }
            if (parse_delim(&Text, ',') == PARSE_ERR)
            {
                err_print("Invalid ','");
                return TYPE_ERR;
            }
            if (parse_mem(&Text, &dig, &rB) == PARSE_ERR)
            {
                err_print("Invalid MEM");
                return TYPE_ERR;
            }
            line->y64bin.codes[1] = HPACK(rA, rB);
            for (int i = 0; i < 8; ++i)
            {
                line->y64bin.codes[i + 2] = ((dig >> 8 * i) & 0xFF);
            }
            break;
        }
        case I_MRMOVQ:
        {
            if (parse_mem(&Text, &dig, &rB) == PARSE_ERR)
            {
                err_print("Invalid MEM");
                return TYPE_ERR;
            }
            if (parse_delim(&Text, ',') == PARSE_ERR)
            {
                err_print("Invalid ','");
                return TYPE_ERR;
            }
            if (parse_reg(&Text, &rA) == PARSE_ERR)
            {
                err_print("Invalid REG");
                return TYPE_ERR;
            }
            line->y64bin.codes[1] = HPACK(rA, rB);
            for (int i = 0; i < 8; ++i)
            {
                line->y64bin.codes[i + 2] = ((dig >> 8 * i) & 0xFF);
            }
            break;
        }
        case I_JMP:
        case I_CALL:
        {
            parse_t type = parse_imm(&Text, &name, &dig);
            if (type == PARSE_ERR)
            {
                err_print("Invalid DEST");
                return TYPE_ERR;
            }
            if (type == PARSE_DIGIT)
            {
                for (int i = 0; i < 8; ++i)
                    line->y64bin.codes[i + 1] = ((dig >> 8 * i) & 0xFF);
            }
            if (type == PARSE_SYMBOL)
                add_reloc(name, &line->y64bin);
            break;
        }
        case I_PUSHQ:
        case I_POPQ:
        {
            if (parse_reg(&Text, &rA) == PARSE_ERR)
            {
                err_print("Invalid REG");
                return TYPE_ERR;
            }
            line->y64bin.codes[1] = HPACK(rA, REG_NONE);
            break;
        }
        case I_DIRECTIVE:
        {
            switch (LOW(INS->code))
            {
            case D_DATA:
            {
                
                parse_t pType;
                pType = parse_data(&Text, &name, &dig);
                if (pType == PARSE_ERR)
                {
                    err_print("parse data error");
                    return TYPE_ERR;
                }
                if (pType == PARSE_SYMBOL)
                {
                    if(INS->bytes < 4) return PARSE_ERR;
                    add_reloc(name, &line->y64bin);
                }
                if (pType == PARSE_DIGIT)
                {
                    for (int i = 0; i < INS->bytes; ++i)
                    {
                        line->y64bin.codes[i] = ((dig >> 8 * i) & 0xFF);
                    }
                }
                break;
            }
            case D_POS:
            {
                if (parse_digit(&Text, &dig) == PARSE_ERR)
                {
                    err_print("parse digit error");
                    return TYPE_ERR;
                }
                vmaddr = dig;
                line->y64bin.addr = vmaddr;
                break;
            }
            case D_ALIGN:
            {
                if (parse_digit(&Text, &dig) == PARSE_ERR)
                {
                    err_print("parse digit error");
                    return TYPE_ERR;
                }
                while (vmaddr % (dig))
                {
                    vmaddr++;
                }
                line->y64bin.addr = vmaddr;
                break;
            }
            }
        }
        }
    return line->type;
}

/*
 * assemble: assemble an y64 file (e.g., 'asum.ys')
 * args
 *     in: point to input file (an y64 assembly file)
 *
 * return
 *     0: success, assmble the y64 file to a list of line_t
 *     -1: error, try to print err information (e.g., instr type and line number)
 */
int assemble(FILE *in)
{
    static char asm_buf[MAX_INSLEN]; /* the current line of asm code */
    line_t *line;
    int slen;
    char *y64asm;

    /* read y64 code line-by-line, and parse them to generate raw y64 binary code list */
    while (fgets(asm_buf, MAX_INSLEN, in) != NULL)
    {
        slen = strlen(asm_buf);
        while ((asm_buf[slen - 1] == '\n') || (asm_buf[slen - 1] == '\r'))
        {
            asm_buf[--slen] = '\0'; /* replace terminator */
        }

        /* store y64 assembly code */
        y64asm = (char *)malloc(sizeof(char) * (slen + 1)); // free in finit
        strcpy(y64asm, asm_buf);

        line = (line_t *)malloc(sizeof(line_t)); // free in finit
        memset(line, '\0', sizeof(line_t));

        line->type = TYPE_COMM;
        line->y64asm = y64asm;
        line->next = NULL;

        line_tail->next = line;
        line_tail = line;
        lineno++;

        if (parse_line(line) == TYPE_ERR)
        {
            return -1;
        }
    }

    lineno = -1;
    return 0;
}

/*
 * relocate: relocate the raw y64 binary code with symbol address
 *
 * return
 *     0: success
 *     -1: error, try to print err information (e.g., addr and symbol)
 */
int relocate(void)
{
    reloc_t *rtmp = reltab->next;
    while (rtmp)
    {
        /* find symbol */
        symbol_t *stmp = find_symbol(rtmp->name);
        /* relocate y64bin according itype */
        if (!stmp)
        {
            err_print("Unknown symbol:'%s'", rtmp->name);
            return -1;
        }

        int offset = 0;
        switch (HIGH(rtmp->y64bin->codes[0]))
        {
        case I_IRMOVQ:
            offset = 2;
            break;
        case I_JMP:
        case I_CALL:
            offset = 1;
            break;
        default:
            offset = 0; //I_DIRECTIVE
        }

        for (int i = 0; i < 8; ++i)
        {
            rtmp->y64bin->codes[i + offset] = (stmp->addr >> i * 8) & 0xff;
        }
        /* next */
        rtmp = rtmp->next;
    }
    return 0;
}

/*
 * binfile: generate the y64 binary file
 * args
 *     out: point to output file (an y64 binary file)
 *
 * return
 *     0: success
 *     -1: error
 */
int binfile(FILE *out)
{
    /* prepare image with y64 binary code */
    line_t *ltmp = line_head->next;
    long addr = 0;
    char ch[MAX_INSLEN];
    for (int i = 0; i < MAX_INSLEN; ++i)
        ch[i] = 0;

    while (ltmp)
    {
        if (ltmp->type == TYPE_INS)
        {
            if (fseek(out, ltmp->y64bin.addr, SEEK_SET) != 0)
                return -1;
            if (fwrite(ltmp->y64bin.codes, 1, ltmp->y64bin.bytes, out) != ltmp->y64bin.bytes)
                return -1;
        }
        ltmp = ltmp->next;
    }
    return 0;
}

/* whether print the readable output to screen or not ? */
bool_t screen = FALSE;

static void hexstuff(char *dest, int value, int len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        char c;
        int h = (value >> 4 * i) & 0xF;
        c = h < 10 ? h + '0' : h - 10 + 'a';
        dest[len - i - 1] = c;
    }
}

void print_line(line_t *line)
{
    char buf[64];

    /* line format: 0xHHH: cccccccccccc | <line> */
    if (line->type == TYPE_INS)
    {
        bin_t *y64bin = &line->y64bin;
        int i;

        strcpy(buf, "  0x000:                      | ");

        hexstuff(buf + 4, y64bin->addr, 3);
        if (y64bin->bytes > 0)
            for (i = 0; i < y64bin->bytes; i++)
                hexstuff(buf + 9 + 2 * i, y64bin->codes[i] & 0xFF, 2);
    }
    else
    {
        strcpy(buf, "                              | ");
    }

    printf("%s%s\n", buf, line->y64asm);
}

/* 
 * print_screen: dump readable binary and assembly code to screen
 * (e.g., Figure 4.8 in ICS book)
 */
void print_screen(void)
{
    line_t *tmp = line_head->next;
    while (tmp != NULL)
    {
        print_line(tmp);
        tmp = tmp->next;
    }
}

/* init and finit */
void init(void)
{
    reltab = (reloc_t *)malloc(sizeof(reloc_t)); // free in finit
    memset(reltab, 0, sizeof(reloc_t));

    symtab = (symbol_t *)malloc(sizeof(symbol_t)); // free in finit
    memset(symtab, 0, sizeof(symbol_t));

    line_head = (line_t *)malloc(sizeof(line_t)); // free in finit
    memset(line_head, 0, sizeof(line_t));
    line_tail = line_head;
    lineno = 0;
}

void finit(void)
{
    reloc_t *rtmp = NULL;
    do
    {
        rtmp = reltab->next;
        if (reltab->name)
            free(reltab->name);
        free(reltab);
        reltab = rtmp;
    } while (reltab);

    symbol_t *stmp = NULL;
    do
    {
        stmp = symtab->next;
        if (symtab->name)
            free(symtab->name);
        free(symtab);
        symtab = stmp;
    } while (symtab);

    line_t *ltmp = NULL;
    do
    {
        ltmp = line_head->next;
        if (line_head->y64asm)
            free(line_head->y64asm);
        free(line_head);
        line_head = ltmp;
    } while (line_head);
}

static void usage(char *pname)
{
    printf("Usage: %s [-v] file.ys\n", pname);
    printf("   -v print the readable output to screen\n");
    exit(0);
}

int main(int argc, char *argv[])
{
    int rootlen;
    char infname[512];
    char outfname[512];
    int nextarg = 1;
    FILE *in = NULL, *out = NULL;

    if (argc < 2)
        usage(argv[0]);

    if (argv[nextarg][0] == '-')
    {
        char flag = argv[nextarg][1];
        switch (flag)
        {
        case 'v':
            screen = TRUE;
            nextarg++;
            break;
        default:
            usage(argv[0]);
        }
    }

    /* parse input file name */
    rootlen = strlen(argv[nextarg]) - 3;
    /* only support the .ys file */
    if (strcmp(argv[nextarg] + rootlen, ".ys"))
        usage(argv[0]);

    if (rootlen > 500)
    {
        err_print("File name too long");
        exit(1);
    }

    /* init */
    init();

    /* assemble .ys file */
    strncpy(infname, argv[nextarg], rootlen);
    strcpy(infname + rootlen, ".ys");
    in = fopen(infname, "r");
    if (!in)
    {
        err_print("Can't open input file '%s'", infname);
        exit(1);
    }

    if (assemble(in) < 0)
    {
        err_print("Assemble y64 code error");
        fclose(in);
        exit(1);
    }
    fclose(in);

    /* relocate binary code */
    if (relocate() < 0)
    {
        err_print("Relocate binary code error");
        exit(1);
    }

    /* generate .bin file */
    strncpy(outfname, argv[nextarg], rootlen);
    strcpy(outfname + rootlen, ".bin");
    out = fopen(outfname, "wb");
    if (!out)
    {
        err_print("Can't open output file '%s'", outfname);
        exit(1);
    }

    if (binfile(out) < 0)
    {
        err_print("Generate binary file error");
        fclose(out);
        exit(1);
    }
    fclose(out);

    /* print to screen (.yo file) */
    if (screen)
        print_screen();

    /* finit */
    finit();
    return 0;
}
