/* Driver template for the LEMON parser generator.
* $Id: lempar.c 36431 2011-04-01 16:55:59Z cmaynard $
*
** Copyright 1991-1995 by D. Richard Hipp.
**
** This library is free software; you can redistribute it and/or
** modify it under the terms of the GNU Library General Public
** License as published by the Free Software Foundation; either
** version 2 of the License, or (at your option) any later version.
**
** This library is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
** Library General Public License for more details.
**
** You should have received a copy of the GNU Library General Public
** License along with this library; if not, write to the
** Free Software Foundation, Inc., 59 Temple Place - Suite 330,
** Boston, MA  02111-1307, USA.
**
** Modified 1997 to make it suitable for use with makeheaders.
* Updated to sqlite lemon version 1.36
*/
/* First off, code is included that follows the "include" declaration
** in the input grammar file. */
#line 1 "./dtd_grammar.lemon"


/* dtd_parser.lemon
* XML dissector for wireshark 
* XML's DTD grammar
*
* Copyright 2005, Luis E. Garcia Ontanon <luis@ontanon.org>
*
* $Id: dtd_grammar.lemon 25937 2008-08-05 21:03:46Z lego $
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
* 
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include <stdio.h>
#include <glib.h>
#include <assert.h>
#include "dtd.h"
#include "dtd_parse.h"

static dtd_named_list_t* dtd_named_list_new(gchar* name, GPtrArray* list) {
	dtd_named_list_t* nl = g_malloc(sizeof(dtd_named_list_t));

	nl->name = name;
	nl->list = list;
	
	return nl;
}

static GPtrArray* g_ptr_array_join(GPtrArray* a, GPtrArray* b){
	
	while(b->len > 0) {
		g_ptr_array_add(a,g_ptr_array_remove_index_fast(b,0));
	}
	
	g_ptr_array_free(b,TRUE);

	return a;
}

#line 85 "dtd_grammar.c"
#include <stdio.h>
#include <string.h>
/* Next is all token values, in a form suitable for use by makeheaders.
** This section will be null unless lemon is run with the -m switch.
*/
/*
** These constants (all generated automatically by the parser generator)
** specify the various kinds of tokens (terminals) that the parser
** understands.
**
** Each symbol here is a terminal symbol in the grammar.
*/
/* Make sure the INTERFACE macro is defined.
*/
#ifndef INTERFACE
# define INTERFACE 1
#endif
/* The next thing included is series of defines which control
** various aspects of the generated parser.
**    YYCODETYPE         is the data type used for storing terminal
**                       and nonterminal numbers.  "unsigned char" is
**                       used if there are fewer than 250 terminals
**                       and nonterminals.  "int" is used otherwise.
**    YYNOCODE           is a number of type YYCODETYPE which corresponds
**                       to no legal terminal or nonterminal number.  This
**                       number is used to fill in empty slots of the hash
**                       table.
**    YYFALLBACK         If defined, this indicates that one or more tokens
**                       have fall-back values which should be used if the
**                       original value of the token will not parse.
**    YYACTIONTYPE       is the data type used for storing terminal
**                       and nonterminal numbers.  "unsigned char" is
**                       used if there are fewer than 250 rules and
**                       states combined.  "int" is used otherwise.
**    DtdParseTOKENTYPE     is the data type used for minor tokens given
**                       directly to the parser from the tokenizer.
**    YYMINORTYPE        is the data type used for all minor tokens.
**                       This is typically a union of many types, one of
**                       which is DtdParseTOKENTYPE.  The entry in the union
**                       for base tokens is called "yy0".
**    YYSTACKDEPTH       is the maximum depth of the parser's stack.  If
**                       zero the stack is dynamically sized using realloc()
**    DtdParseARG_SDECL     A static variable declaration for the %extra_argument
**    DtdParseARG_PDECL     A parameter declaration for the %extra_argument
**    DtdParseARG_STORE     Code to store %extra_argument into yypParser
**    DtdParseARG_FETCH     Code to extract %extra_argument from yypParser
**    YYNSTATE           the combined number of states.
**    YYNRULE            the number of rules in the grammar
**    YYERRORSYMBOL      is the code number of the error symbol.  If not
**                       defined, then do no error processing.
*/
#define YYCODETYPE signed char
#define YYNOCODE 41
#define YYACTIONTYPE signed char
#define DtdParseTOKENTYPE  dtd_token_data_t* 
typedef union {
  DtdParseTOKENTYPE yy0;
  dtd_named_list_t* yy29;
  gchar* yy44;
  GPtrArray* yy59;
  int yy81;
} YYMINORTYPE;
#ifndef YYSTACKDEPTH
#define YYSTACKDEPTH 100
#endif
#define DtdParseARG_SDECL  dtd_build_data_t *bd ;
#define DtdParseARG_PDECL , dtd_build_data_t *bd 
#define DtdParseARG_FETCH  dtd_build_data_t *bd  = yypParser->bd 
#define DtdParseARG_STORE yypParser->bd  = bd 
#define YYNSTATE 71
#define YYNRULE 44
#define YYERRORSYMBOL 24
#define YYERRSYMDT yy81
#define YY_NO_ACTION      (YYNSTATE+YYNRULE+2)
#define YY_ACCEPT_ACTION  (YYNSTATE+YYNRULE+1)
#define YY_ERROR_ACTION   (YYNSTATE+YYNRULE)

/* The yyzerominor constant is used to initialize instances of
** YYMINORTYPE objects to zero. */
static const YYMINORTYPE yyzerominor;

/* Next are the tables used to determine what action to take based on the
** current state and lookahead token.  These tables are used to implement
** functions that take a state number and lookahead value and return an
** action integer.  
**
** Suppose the action integer is N.  Then the action is determined as
** follows
**
**   0 <= N < YYNSTATE                  Shift N.  That is, push the lookahead
**                                      token onto the stack and goto state N.
**
**   YYNSTATE <= N < YYNSTATE+YYNRULE   Reduce by rule N-YYNSTATE.
**
**   N == YYNSTATE+YYNRULE              A syntax error has occurred.
**
**   N == YYNSTATE+YYNRULE+1            The parser accepts its input.
**
**   N == YYNSTATE+YYNRULE+2            No such action.  Denotes unused
**                                      slots in the yy_action[] table.
**
** The action table is constructed as a single large table named yy_action[].
** Given state S and lookahead X, the action is computed as
**
**      yy_action[ yy_shift_ofst[S] + X ]
**
** If the index value yy_shift_ofst[S]+X is out of range or if the value
** yy_lookahead[yy_shift_ofst[S]+X] is not equal to X or if yy_shift_ofst[S]
** is equal to YY_SHIFT_USE_DFLT, it means that the action is not in the table
** and that yy_default[S] should be used instead.  
**
** The formula above is for computing the action when the lookahead is
** a terminal symbol.  If the lookahead is a non-terminal (as occurs after
** a reduce action) then the yy_reduce_ofst[] array is used in place of
** the yy_shift_ofst[] array and YY_REDUCE_USE_DFLT is used in place of
** YY_SHIFT_USE_DFLT.
**
** The following are the tables generated in this section:
**
**  yy_action[]        A single table containing all actions.
**  yy_lookahead[]     A table containing the lookahead for each entry in
**                     yy_action.  Used to detect hash collisions.
**  yy_shift_ofst[]    For each state, the offset into yy_action for
**                     shifting terminals.
**  yy_reduce_ofst[]   For each state, the offset into yy_action for
**                     shifting non-terminals after a reduce.
**  yy_default[]       Default action for each state.
*/
static const YYACTIONTYPE yy_action[] = {
 /*     0 */   116,   23,    7,   69,   70,   38,   25,   40,   41,   42,
 /*    10 */    18,   18,   15,   17,   18,   48,    9,   69,   70,   16,
 /*    20 */    67,   60,    1,    1,   49,   20,    1,    2,   27,   28,
 /*    30 */    59,   59,   29,   53,   59,   51,   22,   50,   54,   55,
 /*    40 */    56,   61,   63,   62,   19,   54,   55,   56,   66,    5,
 /*    50 */    30,   47,   65,   46,    4,   24,   26,   72,   21,   33,
 /*    60 */    34,   43,   11,   12,   44,   52,   21,    2,    1,    8,
 /*    70 */    32,   21,   35,   37,   24,   26,   59,   45,    6,    8,
 /*    80 */    71,   36,   14,   39,   10,   13,   31,  117,   57,   58,
 /*    90 */    64,    3,   68,
};
static const YYCODETYPE yy_lookahead[] = {
 /*     0 */    25,   26,   27,   28,   29,   10,   11,   12,   13,   14,
 /*    10 */     3,    3,   31,   31,    3,    3,   27,   28,   29,   38,
 /*    20 */    39,   39,   15,   15,   12,    1,   15,   15,   21,   21,
 /*    30 */    23,   23,   21,    6,   23,   35,   36,   37,   18,   19,
 /*    40 */    20,   18,   19,   20,   31,   18,   19,   20,   16,   17,
 /*    50 */     2,   35,   39,   37,   22,    7,    8,    0,    1,   28,
 /*    60 */    29,    9,   33,   30,   35,   32,    1,   15,   15,    3,
 /*    70 */     5,    1,    6,   34,    7,    8,   23,   16,   17,    3,
 /*    80 */     0,   32,   31,   12,    3,    3,    3,   40,   16,   16,
 /*    90 */    16,    4,    6,
};
#define YY_SHIFT_USE_DFLT (-6)
#define YY_SHIFT_MAX 32
static const signed char yy_shift_ofst[] = {
 /*     0 */    24,    7,   12,   70,    8,   11,   12,   57,   52,   65,
 /*    10 */    76,   -5,   66,   53,   27,   20,   32,   20,   23,   20,
 /*    20 */    48,   67,   61,   80,   81,   71,   82,   72,   73,   74,
 /*    30 */    83,   87,   86,
};
#define YY_REDUCE_USE_DFLT (-26)
#define YY_REDUCE_MAX 13
static const signed char yy_reduce_ofst[] = {
 /*     0 */   -25,  -19,    0,  -11,  -18,   13,   16,   31,   29,   31,
 /*    10 */    33,   39,   49,   51,
};
static const YYACTIONTYPE yy_default[] = {
 /*     0 */   115,  115,  115,  115,  115,  115,  115,  115,  115,  115,
 /*    10 */   115,  115,  115,  115,  115,  108,  115,  109,  111,  110,
 /*    20 */   115,  115,  115,  115,  115,  115,  115,  115,  115,  115,
 /*    30 */   115,  115,  115,   74,   75,   78,   80,   82,   85,   86,
 /*    40 */    87,   88,   89,   83,   84,   90,   91,   94,   95,   96,
 /*    50 */    92,   93,   81,   79,   97,   98,   99,  100,  101,  104,
 /*    60 */   105,  112,  113,  114,  102,  106,  103,  107,   73,   76,
 /*    70 */    77,
};
#define YY_SZ_ACTTAB (int)(sizeof(yy_action)/sizeof(yy_action[0]))

/* The next table maps tokens into fallback tokens.  If a construct
** like the following:
** 
**      %fallback ID X Y Z.
**
** appears in the grammar, then ID becomes a fallback token for X, Y,
** and Z.  Whenever one of the tokens X, Y, or Z is input to the parser
** but it does not parse, the type of the token is changed to ID and
** the parse is retried before an error is thrown.
*/
#ifdef YYFALLBACK
static const YYCODETYPE yyFallback[] = {
};
#endif /* YYFALLBACK */

/* The following structure represents a single element of the
** parser's stack.  Information stored includes:
**
**   +  The state number for the parser at this level of the stack.
**
**   +  The value of the token stored at this level of the stack.
**      (In other words, the "major" token.)
**
**   +  The semantic value stored at this level of the stack.  This is
**      the information used by the action routines in the grammar.
**      It is sometimes called the "minor" token.
*/
struct yyStackEntry {
  YYACTIONTYPE stateno;  /* The state-number */
  YYCODETYPE major;      /* The major token value.  This is the code
                         ** number for the token at this stack level */
  YYMINORTYPE minor;     /* The user-supplied minor token value.  This
                         ** is the value of the token  */
};
typedef struct yyStackEntry yyStackEntry;

/* The state of the parser is completely contained in an instance of
** the following structure */
struct yyParser {
  int yyidx;                    /* Index of top element in stack */
#ifdef YYTRACKMAXSTACKDEPTH
  int yyidxMax;                 /* Maximum value of yyidx */
#endif
  int yyerrcnt;                 /* Shifts left before out of the error */
  DtdParseARG_SDECL                /* A place to hold %extra_argument */
#if YYSTACKDEPTH<=0
  int yystksz;                  /* Current side of the stack */
  yyStackEntry *yystack;        /* The parser's stack */
#else
  yyStackEntry yystack[YYSTACKDEPTH];  /* The parser's stack */
#endif
};
typedef struct yyParser yyParser;

#ifndef NDEBUG
#include <stdio.h>
static FILE *yyTraceFILE = 0;
static char *yyTracePrompt = 0;
#endif /* NDEBUG */
 
#ifndef NDEBUG
/*
** Turn parser tracing on by giving a stream to which to write the trace
** and a prompt to preface each trace message.  Tracing is turned off
** by making either argument NULL
**
** Inputs:
** <ul>
** <li> A FILE* to which trace output should be written.
**      If NULL, then tracing is turned off.
** <li> A prefix string written at the beginning of every
**      line of trace output.  If NULL, then tracing is
**      turned off.
** </ul>
**
** Outputs:
** None.
*/
void DtdParseTrace(FILE *TraceFILE, char *zTracePrompt){
  yyTraceFILE = TraceFILE;
  yyTracePrompt = zTracePrompt;
  if( yyTraceFILE==0 ) yyTracePrompt = 0;
  else if( yyTracePrompt==0 ) yyTraceFILE = 0;
}
#endif /* NDEBUG */
 
#ifndef NDEBUG
/* For tracing shifts, the names of all terminals and nonterminals
** are required.  The following table supplies these names */
static const char *const yyTokenName[] = {
  "$",             "TAG_START",     "DOCTYPE_KW",    "NAME",        
  "OPEN_BRACKET",  "CLOSE_BRACKET",  "TAG_STOP",      "ATTLIST_KW",  
  "ELEMENT_KW",    "ATT_TYPE",      "ATT_DEF",       "ATT_DEF_WITH_VALUE",
  "QUOTED",        "IMPLIED_KW",    "REQUIRED_KW",   "OPEN_PARENS", 
  "CLOSE_PARENS",  "PIPE",          "STAR",          "PLUS",        
  "QUESTION",      "ELEM_DATA",     "COMMA",         "EMPTY_KW",    
  "error",         "dtd",           "doctype",       "dtd_parts",   
  "element",       "attlist",       "attrib_list",   "sub_elements",
  "attrib",        "att_type",      "att_default",   "enumeration", 
  "enum_list",     "enum_item",     "element_list",  "element_child",
};
#endif /* NDEBUG */

#ifndef NDEBUG
/* For tracing reduce actions, the names of all rules are required.
*/
static const char *const yyRuleName[] = {
 /*   0 */ "dtd ::= doctype",
 /*   1 */ "dtd ::= dtd_parts",
 /*   2 */ "doctype ::= TAG_START DOCTYPE_KW NAME OPEN_BRACKET dtd_parts CLOSE_BRACKET TAG_STOP",
 /*   3 */ "dtd_parts ::= dtd_parts element",
 /*   4 */ "dtd_parts ::= dtd_parts attlist",
 /*   5 */ "dtd_parts ::= element",
 /*   6 */ "dtd_parts ::= attlist",
 /*   7 */ "attlist ::= TAG_START ATTLIST_KW NAME attrib_list TAG_STOP",
 /*   8 */ "element ::= TAG_START ELEMENT_KW NAME sub_elements TAG_STOP",
 /*   9 */ "attrib_list ::= attrib_list attrib",
 /*  10 */ "attrib_list ::= attrib",
 /*  11 */ "attrib ::= NAME att_type att_default",
 /*  12 */ "att_type ::= ATT_TYPE",
 /*  13 */ "att_type ::= enumeration",
 /*  14 */ "att_default ::= ATT_DEF",
 /*  15 */ "att_default ::= ATT_DEF_WITH_VALUE QUOTED",
 /*  16 */ "att_default ::= QUOTED",
 /*  17 */ "att_default ::= IMPLIED_KW",
 /*  18 */ "att_default ::= REQUIRED_KW",
 /*  19 */ "enumeration ::= OPEN_PARENS enum_list CLOSE_PARENS",
 /*  20 */ "enum_list ::= enum_list PIPE enum_item",
 /*  21 */ "enum_list ::= enum_item",
 /*  22 */ "enum_list ::= enumeration",
 /*  23 */ "enum_list ::= enum_list PIPE enumeration",
 /*  24 */ "enum_item ::= NAME",
 /*  25 */ "enum_item ::= QUOTED",
 /*  26 */ "sub_elements ::= sub_elements STAR",
 /*  27 */ "sub_elements ::= sub_elements PLUS",
 /*  28 */ "sub_elements ::= sub_elements QUESTION",
 /*  29 */ "sub_elements ::= OPEN_PARENS ELEM_DATA CLOSE_PARENS",
 /*  30 */ "sub_elements ::= OPEN_PARENS element_list COMMA ELEM_DATA CLOSE_PARENS",
 /*  31 */ "sub_elements ::= OPEN_PARENS element_list PIPE ELEM_DATA CLOSE_PARENS",
 /*  32 */ "sub_elements ::= OPEN_PARENS element_list CLOSE_PARENS",
 /*  33 */ "sub_elements ::= EMPTY_KW",
 /*  34 */ "element_list ::= element_list COMMA element_child",
 /*  35 */ "element_list ::= element_list PIPE element_child",
 /*  36 */ "element_list ::= element_child",
 /*  37 */ "element_list ::= sub_elements",
 /*  38 */ "element_list ::= element_list COMMA sub_elements",
 /*  39 */ "element_list ::= element_list PIPE sub_elements",
 /*  40 */ "element_child ::= NAME",
 /*  41 */ "element_child ::= NAME STAR",
 /*  42 */ "element_child ::= NAME QUESTION",
 /*  43 */ "element_child ::= NAME PLUS",
};
#endif /* NDEBUG */


#if YYSTACKDEPTH<=0
/*
** Try to increase the size of the parser stack.
*/
static void yyGrowStack(yyParser *p){
  int newSize;
  yyStackEntry *pNew;

  newSize = p->yystksz*2 + 100;
  pNew = realloc(p->yystack, newSize*sizeof(pNew[0]));
  if( pNew ){
    p->yystack = pNew;
    p->yystksz = newSize;
#ifndef NDEBUG
    if( yyTraceFILE ){
      fprintf(yyTraceFILE,"%sStack grows to %d entries!\n",
              yyTracePrompt, p->yystksz);
    }
#endif
  }
}
#endif

/*
** This function allocates a new parser.
** The only argument is a pointer to a function which works like
** malloc.
**
** Inputs:
** A pointer to the function used to allocate memory.
**
** Outputs:
** A pointer to a parser.  This pointer is used in subsequent calls
** to DtdParse and DtdParseFree.
*/
#if GLIB_CHECK_VERSION(2,16,0)
void *DtdParseAlloc(void *(*mallocProc)(gsize)){
  yyParser *pParser;
  pParser = (yyParser*)(*mallocProc)( (gsize)sizeof(yyParser) );
#else
void *DtdParseAlloc(void *(*mallocProc)(gulong)){
  yyParser *pParser;
  pParser = (yyParser*)(*mallocProc)( (gulong)sizeof(yyParser) );
#endif
  if( pParser ){
    pParser->yyidx = -1;
#ifdef YYTRACKMAXSTACKDEPTH
    pParser->yyidxMax = 0;
#endif
#if YYSTACKDEPTH<=0
    yyGrowStack(pParser);
#endif
  }
  return pParser;
}

/* The following function deletes the value associated with a
** symbol.  The symbol can be either a terminal or nonterminal.
** "yymajor" is the symbol code, and "yypminor" is a pointer to
** the value.
*/
static void yy_destructor(YYCODETYPE yymajor, YYMINORTYPE *yypminor){
  switch( yymajor ){
    /* Here is inserted the actions which take place when a
    ** terminal or non-terminal is destroyed.  This can happen
    ** when the symbol is popped from the stack during a
    ** reduce or during error processing or when a parser is
    ** being destroyed before it is finished parsing.
    **
    ** Note: during a reduce, the only symbols destroyed are those
    ** which appear on the RHS of the rule, but which are not used
    ** inside the C code.
    */
      /* TERMINAL Destructor */
    case 1: /* TAG_START */
    case 2: /* DOCTYPE_KW */
    case 3: /* NAME */
    case 4: /* OPEN_BRACKET */
    case 5: /* CLOSE_BRACKET */
    case 6: /* TAG_STOP */
    case 7: /* ATTLIST_KW */
    case 8: /* ELEMENT_KW */
    case 9: /* ATT_TYPE */
    case 10: /* ATT_DEF */
    case 11: /* ATT_DEF_WITH_VALUE */
    case 12: /* QUOTED */
    case 13: /* IMPLIED_KW */
    case 14: /* REQUIRED_KW */
    case 15: /* OPEN_PARENS */
    case 16: /* CLOSE_PARENS */
    case 17: /* PIPE */
    case 18: /* STAR */
    case 19: /* PLUS */
    case 20: /* QUESTION */
    case 21: /* ELEM_DATA */
    case 22: /* COMMA */
    case 23: /* EMPTY_KW */
{
#line 62 "./dtd_grammar.lemon"
 
	if ((yypminor->yy0)) {
		if ((yypminor->yy0)->text) g_free((yypminor->yy0)->text);
		if ((yypminor->yy0)->location) g_free((yypminor->yy0)->location);
		g_free((yypminor->yy0));
	}

#line 526 "dtd_grammar.c"
}
      break;
    default:  break;   /* If no destructor action specified: do nothing */
  }
}

/*
** Pop the parser's stack once.
**
** If there is a destructor routine associated with the token which
** is popped from the stack, then call it.
**
** Return the major token number for the symbol popped.
*/
static int yy_pop_parser_stack(yyParser *pParser){
  YYCODETYPE yymajor;
  yyStackEntry *yytos;

  if( pParser->yyidx<0 ) return 0;
  yytos = &pParser->yystack[pParser->yyidx];
#ifndef NDEBUG
  if( yyTraceFILE ){
    fprintf(yyTraceFILE,"%sPopping %s\n",
      yyTracePrompt,
     yyTokenName[yytos->major]);
  }
#endif
  yymajor = yytos->major;
  yy_destructor( yymajor, &yytos->minor);
  pParser->yyidx--;
  return yymajor;
}

/*
** Deallocate and destroy a parser.  Destructors are all called for
** all stack elements before shutting the parser down.
**
** Inputs:
** <ul>
** <li>  A pointer to the parser.  This should be a pointer
**       obtained from DtdParseAlloc.
** <li>  A pointer to a function used to reclaim memory obtained
**       from malloc.
** </ul>
*/
void DtdParseFree(
  void *p,                 /* The parser to be deleted */
  void (*freeProc)(void*)  /* Function used to reclaim memory */
){
  yyParser *pParser = (yyParser*)p;
  if( pParser==0 ) return;
  while( pParser->yyidx>=0 ) yy_pop_parser_stack(pParser);
#if YYSTACKDEPTH<=0
  free(pParser->yystack);
#endif
  (*freeProc)(pParser);
}

/*
** Return the peak depth of the stack for a parser.
*/
#ifdef YYTRACKMAXSTACKDEPTH
int DtdParseStackPeak(void *p){
  yyParser *pParser = (yyParser*)p;
  return pParser->yyidxMax;
}
#endif

/*
** Find the appropriate action for a parser given the terminal
** look-ahead token iLookAhead.
**
** If the look-ahead token is YYNOCODE, then check to see if the action is
** independent of the look-ahead.  If it is, return the action, otherwise
** return YY_NO_ACTION.
*/
static int yy_find_shift_action(
  yyParser *pParser,        /* The parser */
  YYCODETYPE iLookAhead     /* The look-ahead token */
){
  int i;
  int stateno = pParser->yystack[pParser->yyidx].stateno;

  if( stateno>YY_SHIFT_MAX || (i = yy_shift_ofst[stateno])==YY_SHIFT_USE_DFLT ){
    return yy_default[stateno];
  }
  assert( iLookAhead!=YYNOCODE );
  i += iLookAhead;
  if( i<0 || i>=YY_SZ_ACTTAB || yy_lookahead[i]!=iLookAhead ){
    if( iLookAhead>0 ){
#ifdef YYFALLBACK
      int iFallback;            /* Fallback token */
      if( iLookAhead<sizeof(yyFallback)/sizeof(yyFallback[0])
             && (iFallback = yyFallback[iLookAhead])!=0 ){
#ifndef NDEBUG
        if( yyTraceFILE ){
          fprintf(yyTraceFILE, "%sFALLBACK %s => %s\n",
             yyTracePrompt, yyTokenName[iLookAhead], yyTokenName[iFallback]);
        }
#endif
        return yy_find_shift_action(pParser, iFallback);
      }
#endif
#ifdef YYWILDCARD
	  {
      int j = i - iLookAhead + YYWILDCARD;
      if( j>=0 && j<YY_SZ_ACTTAB && yy_lookahead[j]==YYWILDCARD ){
#ifndef NDEBUG
        if( yyTraceFILE ){
          fprintf(yyTraceFILE, "%sWILDCARD %s => %s\n",
             yyTracePrompt, yyTokenName[iLookAhead], yyTokenName[YYWILDCARD]);
        }
#endif /* NDEBUG */
        return yy_action[j];
      }
	  }
#endif /* YYWILDCARD */
    }
    return yy_default[stateno];
  }else{
    return yy_action[i];
  }
}

/*
** Find the appropriate action for a parser given the non-terminal
** look-ahead token iLookAhead.
**
** If the look-ahead token is YYNOCODE, then check to see if the action is
** independent of the look-ahead.  If it is, return the action, otherwise
** return YY_NO_ACTION.
*/
static int yy_find_reduce_action(
  int stateno,              /* Current state number */
  YYCODETYPE iLookAhead     /* The look-ahead token */
){
  int i;
#ifdef YYERRORSYMBOL
  if( stateno>YY_REDUCE_MAX ){
    return yy_default[stateno];
  }
#else
  assert( stateno<=YY_REDUCE_MAX );
#endif
  i = yy_reduce_ofst[stateno];
  assert( i!=YY_REDUCE_USE_DFLT );
  assert( iLookAhead!=YYNOCODE );
  i += iLookAhead;
#ifdef YYERRORSYMBOL
  if( i<0 || i>=YY_SZ_ACTTAB || yy_lookahead[i]!=iLookAhead ){
    return yy_default[stateno];
  }
#else
  assert( i>=0 && i<YY_SZ_ACTTAB );
  assert( yy_lookahead[i]==iLookAhead );
#endif
  return yy_action[i];
}

/*
** The following routine is called if the stack overflows.
*/
static void yyStackOverflow(yyParser *yypParser, YYMINORTYPE *yypMinor _U_){
   DtdParseARG_FETCH;
   yypParser->yyidx--;
#ifndef NDEBUG
   if( yyTraceFILE ){
     fprintf(yyTraceFILE,"%sStack Overflow!\n",yyTracePrompt);
   }
#endif
   while( yypParser->yyidx>=0 ) yy_pop_parser_stack(yypParser);
   /* Here code is inserted which will execute if the parser
   ** stack every overflows */
   DtdParseARG_STORE; /* Suppress warning about unused %extra_argument var */
}

/*
** Perform a shift action.
*/
static void yy_shift(
  yyParser *yypParser,          /* The parser to be shifted */
  int yyNewState,               /* The new state to shift in */
  int yyMajor,                  /* The major token to shift in */
  YYMINORTYPE *yypMinor         /* Pointer to the minor token to shift in */
){
  yyStackEntry *yytos;
  yypParser->yyidx++;
#ifdef YYTRACKMAXSTACKDEPTH
  if( yypParser->yyidx>yypParser->yyidxMax ){
    yypParser->yyidxMax = yypParser->yyidx;
  }
#endif
#if YYSTACKDEPTH>0
  if( yypParser->yyidx>=YYSTACKDEPTH ){
    yyStackOverflow(yypParser, yypMinor);
    return;
  }
#else
  if( yypParser->yyidx>=yypParser->yystksz ){
    yyGrowStack(yypParser);
    if( yypParser->yyidx>=yypParser->yystksz ){
      yyStackOverflow(yypParser, yypMinor);
      return;
    }
  }
#endif
  yytos = &yypParser->yystack[yypParser->yyidx];
  yytos->stateno = yyNewState;
  yytos->major = yyMajor;
  yytos->minor = *yypMinor;
#ifndef NDEBUG
  if( yyTraceFILE && yypParser->yyidx>0 ){
    int i;
    fprintf(yyTraceFILE,"%sShift %d\n",yyTracePrompt,yyNewState);
    fprintf(yyTraceFILE,"%sStack:",yyTracePrompt);
    for(i=1; i<=yypParser->yyidx; i++)
      fprintf(yyTraceFILE," %s",yyTokenName[yypParser->yystack[i].major]);
    fprintf(yyTraceFILE,"\n");
  }
#endif
}

/* The following table contains information about every rule that
** is used during the reduce.
*/
static const struct {
  YYCODETYPE lhs;         /* Symbol on the left-hand side of the rule */
  unsigned char nrhs;     /* Number of right-hand side symbols in the rule */
} yyRuleInfo[] = {
  { 25, 1 },
  { 25, 1 },
  { 26, 7 },
  { 27, 2 },
  { 27, 2 },
  { 27, 1 },
  { 27, 1 },
  { 29, 5 },
  { 28, 5 },
  { 30, 2 },
  { 30, 1 },
  { 32, 3 },
  { 33, 1 },
  { 33, 1 },
  { 34, 1 },
  { 34, 2 },
  { 34, 1 },
  { 34, 1 },
  { 34, 1 },
  { 35, 3 },
  { 36, 3 },
  { 36, 1 },
  { 36, 1 },
  { 36, 3 },
  { 37, 1 },
  { 37, 1 },
  { 31, 2 },
  { 31, 2 },
  { 31, 2 },
  { 31, 3 },
  { 31, 5 },
  { 31, 5 },
  { 31, 3 },
  { 31, 1 },
  { 38, 3 },
  { 38, 3 },
  { 38, 1 },
  { 38, 1 },
  { 38, 3 },
  { 38, 3 },
  { 39, 1 },
  { 39, 2 },
  { 39, 2 },
  { 39, 2 },
};

static void yy_accept(yyParser *yypParser);  /* Forward declaration */

/*
** Perform a reduce action and the shift that must immediately
** follow the reduce.
*/
static void yy_reduce(
  yyParser *yypParser,         /* The parser */
  int yyruleno                 /* Number of the rule by which to reduce */
){
  int yygoto;                     /* The next state */
  int yyact;                      /* The next action */
  YYMINORTYPE yygotominor;        /* The LHS of the rule reduced */
  yyStackEntry *yymsp;            /* The top of the parser's stack */
  int yysize;                     /* Amount to pop the stack */
  DtdParseARG_FETCH;
  yymsp = &yypParser->yystack[yypParser->yyidx];
#ifndef NDEBUG
  if( yyTraceFILE && yyruleno>=0 
        && yyruleno<(int)(sizeof(yyRuleName)/sizeof(yyRuleName[0])) ){
    fprintf(yyTraceFILE, "%sReduce [%s].\n", yyTracePrompt,
      yyRuleName[yyruleno]);
  }
#endif /* NDEBUG */

  /* Silence complaints from purify about yygotominor being uninitialized
  ** in some cases when it is copied into the stack after the following
  ** switch.  yygotominor is uninitialized when a rule reduces that does
  ** not set the value of its left-hand side nonterminal.  Leaving the
  ** value of the nonterminal uninitialized is utterly harmless as long
  ** as the value is never used.  So really the only thing this code
  ** accomplishes is to quieten purify.  
  **
  ** 2007-01-16:  The wireshark project (www.wireshark.org) reports that
  ** without this code, their parser segfaults.  I'm not sure what there
  ** parser is doing to make this happen.  This is the second bug report
  ** from wireshark this week.  Clearly they are stressing Lemon in ways
  ** that it has not been previously stressed...  (SQLite ticket #2172)
  */
  /*memset(&yygotominor, 0, sizeof(yygotominor));*/
  yygotominor = yyzerominor;
  switch( yyruleno ){
  /* Beginning here are the reduction cases.  A typical example
  ** follows:
  **   case 0:
  **  #line <lineno> <grammarfile>
  **     { ... }           // User supplied code
  **  #line <lineno> <thisfile>
  **     break;
  */
      case 0: /* dtd ::= doctype */
      case 1: /* dtd ::= dtd_parts */
      case 13: /* att_type ::= enumeration */
      case 21: /* enum_list ::= enum_item */
      case 22: /* enum_list ::= enumeration */
#line 85 "./dtd_grammar.lemon"
{
}
#line 859 "dtd_grammar.c"
        break;
      case 2: /* doctype ::= TAG_START DOCTYPE_KW NAME OPEN_BRACKET dtd_parts CLOSE_BRACKET TAG_STOP */
#line 88 "./dtd_grammar.lemon"
{
    dtd_named_list_t* root;
    GPtrArray* root_elems = g_ptr_array_new();
    guint i;

    if(! bd->proto_name) {
        bd->proto_name = yymsp[-4].minor.yy0->text;
    }

    if(bd->proto_root)
        g_free(bd->proto_root);

	bd->proto_root = yymsp[-4].minor.yy0->text;
    
	g_strdown(bd->proto_name);
    
    for( i = 0; i< bd->elements->len; i++) {
        dtd_named_list_t* el = g_ptr_array_index(bd->elements,i);
        
        g_ptr_array_add(root_elems,g_strdup(el->name));
    }
    
    root = dtd_named_list_new(g_strdup(yymsp[-4].minor.yy0->text),root_elems);
    
    g_ptr_array_add(bd->elements,root);
    
    g_free(yymsp[-4].minor.yy0->location);
    g_free(yymsp[-4].minor.yy0);

  yy_destructor(1,&yymsp[-6].minor);
  yy_destructor(2,&yymsp[-5].minor);
  yy_destructor(4,&yymsp[-3].minor);
  yy_destructor(5,&yymsp[-1].minor);
  yy_destructor(6,&yymsp[0].minor);
}
#line 898 "dtd_grammar.c"
        break;
      case 3: /* dtd_parts ::= dtd_parts element */
      case 5: /* dtd_parts ::= element */
#line 119 "./dtd_grammar.lemon"
{ g_ptr_array_add(bd->elements,yymsp[0].minor.yy29); }
#line 904 "dtd_grammar.c"
        break;
      case 4: /* dtd_parts ::= dtd_parts attlist */
      case 6: /* dtd_parts ::= attlist */
#line 120 "./dtd_grammar.lemon"
{ g_ptr_array_add(bd->attributes,yymsp[0].minor.yy29); }
#line 910 "dtd_grammar.c"
        break;
      case 7: /* attlist ::= TAG_START ATTLIST_KW NAME attrib_list TAG_STOP */
#line 125 "./dtd_grammar.lemon"
{
    g_strdown(yymsp[-2].minor.yy0->text);
    yygotominor.yy29 = dtd_named_list_new(yymsp[-2].minor.yy0->text,yymsp[-1].minor.yy59);
    g_free(yymsp[-2].minor.yy0->location);
    g_free(yymsp[-2].minor.yy0);
  yy_destructor(1,&yymsp[-4].minor);
  yy_destructor(7,&yymsp[-3].minor);
  yy_destructor(6,&yymsp[0].minor);
}
#line 923 "dtd_grammar.c"
        break;
      case 8: /* element ::= TAG_START ELEMENT_KW NAME sub_elements TAG_STOP */
#line 133 "./dtd_grammar.lemon"
{
    g_strdown(yymsp[-2].minor.yy0->text);
    yygotominor.yy29 = dtd_named_list_new(yymsp[-2].minor.yy0->text,yymsp[-1].minor.yy59);
    g_free(yymsp[-2].minor.yy0->location);
    g_free(yymsp[-2].minor.yy0);
  yy_destructor(1,&yymsp[-4].minor);
  yy_destructor(8,&yymsp[-3].minor);
  yy_destructor(6,&yymsp[0].minor);
}
#line 936 "dtd_grammar.c"
        break;
      case 9: /* attrib_list ::= attrib_list attrib */
#line 141 "./dtd_grammar.lemon"
{ g_ptr_array_add(yymsp[-1].minor.yy59,yymsp[0].minor.yy44); yygotominor.yy59 = yymsp[-1].minor.yy59; }
#line 941 "dtd_grammar.c"
        break;
      case 10: /* attrib_list ::= attrib */
#line 142 "./dtd_grammar.lemon"
{ yygotominor.yy59 = g_ptr_array_new(); g_ptr_array_add(yygotominor.yy59,yymsp[0].minor.yy44);  }
#line 946 "dtd_grammar.c"
        break;
      case 11: /* attrib ::= NAME att_type att_default */
#line 145 "./dtd_grammar.lemon"
{
	yygotominor.yy44 = yymsp[-2].minor.yy0->text;
	g_strdown(yygotominor.yy44);
    g_free(yymsp[-2].minor.yy0->location);
    g_free(yymsp[-2].minor.yy0);
}
#line 956 "dtd_grammar.c"
        break;
      case 12: /* att_type ::= ATT_TYPE */
#line 152 "./dtd_grammar.lemon"
{
  yy_destructor(9,&yymsp[0].minor);
}
#line 963 "dtd_grammar.c"
        break;
      case 14: /* att_default ::= ATT_DEF */
#line 155 "./dtd_grammar.lemon"
{
  yy_destructor(10,&yymsp[0].minor);
}
#line 970 "dtd_grammar.c"
        break;
      case 15: /* att_default ::= ATT_DEF_WITH_VALUE QUOTED */
#line 156 "./dtd_grammar.lemon"
{
  yy_destructor(11,&yymsp[-1].minor);
  yy_destructor(12,&yymsp[0].minor);
}
#line 978 "dtd_grammar.c"
        break;
      case 16: /* att_default ::= QUOTED */
      case 25: /* enum_item ::= QUOTED */
#line 157 "./dtd_grammar.lemon"
{
  yy_destructor(12,&yymsp[0].minor);
}
#line 986 "dtd_grammar.c"
        break;
      case 17: /* att_default ::= IMPLIED_KW */
#line 158 "./dtd_grammar.lemon"
{
  yy_destructor(13,&yymsp[0].minor);
}
#line 993 "dtd_grammar.c"
        break;
      case 18: /* att_default ::= REQUIRED_KW */
#line 159 "./dtd_grammar.lemon"
{
  yy_destructor(14,&yymsp[0].minor);
}
#line 1000 "dtd_grammar.c"
        break;
      case 19: /* enumeration ::= OPEN_PARENS enum_list CLOSE_PARENS */
#line 161 "./dtd_grammar.lemon"
{
  yy_destructor(15,&yymsp[-2].minor);
  yy_destructor(16,&yymsp[0].minor);
}
#line 1008 "dtd_grammar.c"
        break;
      case 20: /* enum_list ::= enum_list PIPE enum_item */
      case 23: /* enum_list ::= enum_list PIPE enumeration */
#line 163 "./dtd_grammar.lemon"
{
  yy_destructor(17,&yymsp[-1].minor);
}
#line 1016 "dtd_grammar.c"
        break;
      case 24: /* enum_item ::= NAME */
#line 168 "./dtd_grammar.lemon"
{
  yy_destructor(3,&yymsp[0].minor);
}
#line 1023 "dtd_grammar.c"
        break;
      case 26: /* sub_elements ::= sub_elements STAR */
#line 173 "./dtd_grammar.lemon"
{yygotominor.yy59=yymsp[-1].minor.yy59;  yy_destructor(18,&yymsp[0].minor);
}
#line 1029 "dtd_grammar.c"
        break;
      case 27: /* sub_elements ::= sub_elements PLUS */
#line 174 "./dtd_grammar.lemon"
{yygotominor.yy59=yymsp[-1].minor.yy59;  yy_destructor(19,&yymsp[0].minor);
}
#line 1035 "dtd_grammar.c"
        break;
      case 28: /* sub_elements ::= sub_elements QUESTION */
#line 175 "./dtd_grammar.lemon"
{yygotominor.yy59=yymsp[-1].minor.yy59;  yy_destructor(20,&yymsp[0].minor);
}
#line 1041 "dtd_grammar.c"
        break;
      case 29: /* sub_elements ::= OPEN_PARENS ELEM_DATA CLOSE_PARENS */
#line 176 "./dtd_grammar.lemon"
{ yygotominor.yy59 = g_ptr_array_new();   yy_destructor(15,&yymsp[-2].minor);
  yy_destructor(21,&yymsp[-1].minor);
  yy_destructor(16,&yymsp[0].minor);
}
#line 1049 "dtd_grammar.c"
        break;
      case 30: /* sub_elements ::= OPEN_PARENS element_list COMMA ELEM_DATA CLOSE_PARENS */
#line 177 "./dtd_grammar.lemon"
{ yygotominor.yy59 = yymsp[-3].minor.yy59;   yy_destructor(15,&yymsp[-4].minor);
  yy_destructor(22,&yymsp[-2].minor);
  yy_destructor(21,&yymsp[-1].minor);
  yy_destructor(16,&yymsp[0].minor);
}
#line 1058 "dtd_grammar.c"
        break;
      case 31: /* sub_elements ::= OPEN_PARENS element_list PIPE ELEM_DATA CLOSE_PARENS */
#line 178 "./dtd_grammar.lemon"
{ yygotominor.yy59 = yymsp[-3].minor.yy59;   yy_destructor(15,&yymsp[-4].minor);
  yy_destructor(17,&yymsp[-2].minor);
  yy_destructor(21,&yymsp[-1].minor);
  yy_destructor(16,&yymsp[0].minor);
}
#line 1067 "dtd_grammar.c"
        break;
      case 32: /* sub_elements ::= OPEN_PARENS element_list CLOSE_PARENS */
#line 179 "./dtd_grammar.lemon"
{ yygotominor.yy59 = yymsp[-1].minor.yy59;   yy_destructor(15,&yymsp[-2].minor);
  yy_destructor(16,&yymsp[0].minor);
}
#line 1074 "dtd_grammar.c"
        break;
      case 33: /* sub_elements ::= EMPTY_KW */
#line 180 "./dtd_grammar.lemon"
{ yygotominor.yy59 = g_ptr_array_new();   yy_destructor(23,&yymsp[0].minor);
}
#line 1080 "dtd_grammar.c"
        break;
      case 34: /* element_list ::= element_list COMMA element_child */
#line 183 "./dtd_grammar.lemon"
{ g_ptr_array_add(yymsp[-2].minor.yy59,yymsp[0].minor.yy44); yygotominor.yy59 = yymsp[-2].minor.yy59;   yy_destructor(22,&yymsp[-1].minor);
}
#line 1086 "dtd_grammar.c"
        break;
      case 35: /* element_list ::= element_list PIPE element_child */
#line 184 "./dtd_grammar.lemon"
{ g_ptr_array_add(yymsp[-2].minor.yy59,yymsp[0].minor.yy44); yygotominor.yy59 = yymsp[-2].minor.yy59;   yy_destructor(17,&yymsp[-1].minor);
}
#line 1092 "dtd_grammar.c"
        break;
      case 36: /* element_list ::= element_child */
#line 185 "./dtd_grammar.lemon"
{ yygotominor.yy59 = g_ptr_array_new(); g_ptr_array_add(yygotominor.yy59,yymsp[0].minor.yy44); }
#line 1097 "dtd_grammar.c"
        break;
      case 37: /* element_list ::= sub_elements */
#line 186 "./dtd_grammar.lemon"
{ yygotominor.yy59 = yymsp[0].minor.yy59; }
#line 1102 "dtd_grammar.c"
        break;
      case 38: /* element_list ::= element_list COMMA sub_elements */
#line 187 "./dtd_grammar.lemon"
{ yygotominor.yy59 = g_ptr_array_join(yymsp[-2].minor.yy59,yymsp[0].minor.yy59);   yy_destructor(22,&yymsp[-1].minor);
}
#line 1108 "dtd_grammar.c"
        break;
      case 39: /* element_list ::= element_list PIPE sub_elements */
#line 188 "./dtd_grammar.lemon"
{ yygotominor.yy59 = g_ptr_array_join(yymsp[-2].minor.yy59,yymsp[0].minor.yy59);   yy_destructor(17,&yymsp[-1].minor);
}
#line 1114 "dtd_grammar.c"
        break;
      case 40: /* element_child ::= NAME */
#line 191 "./dtd_grammar.lemon"
{
	yygotominor.yy44 = yymsp[0].minor.yy0->text;
	g_strdown(yygotominor.yy44);
    g_free(yymsp[0].minor.yy0->location);
    g_free(yymsp[0].minor.yy0);
}
#line 1124 "dtd_grammar.c"
        break;
      case 41: /* element_child ::= NAME STAR */
#line 198 "./dtd_grammar.lemon"
{
	yygotominor.yy44 = yymsp[-1].minor.yy0->text;
	g_strdown(yygotominor.yy44);
    g_free(yymsp[-1].minor.yy0->location);
    g_free(yymsp[-1].minor.yy0);
  yy_destructor(18,&yymsp[0].minor);
}
#line 1135 "dtd_grammar.c"
        break;
      case 42: /* element_child ::= NAME QUESTION */
#line 205 "./dtd_grammar.lemon"
{
	yygotominor.yy44 = yymsp[-1].minor.yy0->text;
	g_strdown(yygotominor.yy44);
    g_free(yymsp[-1].minor.yy0->location);
    g_free(yymsp[-1].minor.yy0);
  yy_destructor(20,&yymsp[0].minor);
}
#line 1146 "dtd_grammar.c"
        break;
      case 43: /* element_child ::= NAME PLUS */
#line 212 "./dtd_grammar.lemon"
{
	yygotominor.yy44 = yymsp[-1].minor.yy0->text;
	g_strdown(yygotominor.yy44);
    g_free(yymsp[-1].minor.yy0->location);
    g_free(yymsp[-1].minor.yy0);
  yy_destructor(19,&yymsp[0].minor);
}
#line 1157 "dtd_grammar.c"
        break;
  };
  yygoto = yyRuleInfo[yyruleno].lhs;
  yysize = yyRuleInfo[yyruleno].nrhs;
  yypParser->yyidx -= yysize;
  yyact = yy_find_reduce_action(yymsp[-yysize].stateno,(YYCODETYPE)yygoto);
  if( yyact < YYNSTATE ){
#ifdef NDEBUG
    /* If we are not debugging and the reduce action popped at least
    ** one element off the stack, then we can push the new element back
    ** onto the stack here, and skip the stack overflow test in yy_shift().
    ** That gives a significant speed improvement. */
    if( yysize ){
      yypParser->yyidx++;
      yymsp -= yysize-1;
      yymsp->stateno = yyact;
      yymsp->major = yygoto;
      yymsp->minor = yygotominor;
    }else
#endif
    {
      yy_shift(yypParser,yyact,yygoto,&yygotominor);
    }
  }else{
    assert( yyact == YYNSTATE + YYNRULE + 1 );
    yy_accept(yypParser);
  }
}

/*
** The following code executes when the parse fails
*/
static void yy_parse_failed(
  yyParser *yypParser           /* The parser */
){
  DtdParseARG_FETCH;
#ifndef NDEBUG
  if( yyTraceFILE ){
    fprintf(yyTraceFILE,"%sFail!\n",yyTracePrompt);
  }
#endif
  while( yypParser->yyidx>=0 ) yy_pop_parser_stack(yypParser);
  /* Here code is inserted which will be executed whenever the
  ** parser fails */
#line 77 "./dtd_grammar.lemon"

	g_string_append_printf(bd->error,"DTD parsing failure\n");
#line 1207 "dtd_grammar.c"
  DtdParseARG_STORE; /* Suppress warning about unused %extra_argument variable */
}

/*
** The following code executes when a syntax error first occurs.
*/
static void yy_syntax_error(
  yyParser *yypParser _U_,       /* The parser */
  int yymajor _U_,               /* The major type of the error token */
  YYMINORTYPE yyminor            /* The minor type of the error token */
){
  DtdParseARG_FETCH;
#define TOKEN (yyminor.yy0)
#line 70 "./dtd_grammar.lemon"

	if (!TOKEN)
		g_string_append_printf(bd->error,"syntax error at end of file");
	else 
		g_string_append_printf(bd->error,"syntax error in %s at or before '%s': \n", TOKEN->location,TOKEN->text);
#line 1229 "dtd_grammar.c"
  DtdParseARG_STORE; /* Suppress warning about unused %extra_argument variable */
}

/*
** The following is executed when the parser accepts
*/
static void yy_accept(
  yyParser *yypParser           /* The parser */
){
  DtdParseARG_FETCH;
#ifndef NDEBUG
  if( yyTraceFILE ){
    fprintf(yyTraceFILE,"%sAccept!\n",yyTracePrompt);
  }
#endif
  while( yypParser->yyidx>=0 ) yy_pop_parser_stack(yypParser);
  /* Here code is inserted which will be executed whenever the
  ** parser accepts */
  DtdParseARG_STORE; /* Suppress warning about unused %extra_argument variable */
}

/* The main parser program.
** The first argument is a pointer to a structure obtained from
** "DtdParseAlloc" which describes the current state of the parser.
** The second argument is the major token number.  The third is
** the minor token.  The fourth optional argument is whatever the
** user wants (and specified in the grammar) and is available for
** use by the action routines.
**
** Inputs:
** <ul>
** <li> A pointer to the parser (an opaque structure.)
** <li> The major token number.
** <li> The minor token number.
** <li> An option argument of a grammar-specified type.
** </ul>
**
** Outputs:
** None.
*/
void DtdParse(
  void *yyp,                   /* The parser */
  int yymajor,                 /* The major token code number */
  DtdParseTOKENTYPE yyminor       /* The value for the token */
  DtdParseARG_PDECL               /* Optional %extra_argument parameter */
){
  YYMINORTYPE yyminorunion;
  int yyact;            /* The parser action. */
  int yyendofinput;     /* True if we are at the end of input */
#ifdef YYERRORSYMBOL
   int yyerrorhit = 0;   /* True if yymajor has invoked an error */
#endif
  yyParser *yypParser;  /* The parser */

  /* (re)initialize the parser, if necessary */
  yypParser = (yyParser*)yyp;
  if( yypParser->yyidx<0 ){
#if YYSTACKDEPTH<=0
    if( yypParser->yystksz <=0 ){
      /*memset(&yyminorunion, 0, sizeof(yyminorunion));*/
      yyminorunion = yyzerominor;
       yyStackOverflow(yypParser, &yyminorunion);
      return;
    }
#endif
    yypParser->yyidx = 0;
    yypParser->yyerrcnt = -1;
    yypParser->yystack[0].stateno = 0;
    yypParser->yystack[0].major = 0;
  }
  yyminorunion.yy0 = yyminor;
  yyendofinput = (yymajor==0);
  DtdParseARG_STORE;

#ifndef NDEBUG
  if( yyTraceFILE ){
    fprintf(yyTraceFILE,"%sInput %s\n",yyTracePrompt,yyTokenName[yymajor]);
  }
#endif

  do{
    yyact = yy_find_shift_action(yypParser,(YYCODETYPE)yymajor);
    if( yyact<YYNSTATE ){
	  assert( !yyendofinput );  /* Impossible to shift the $ token */
      yy_shift(yypParser,yyact,yymajor,&yyminorunion);
      yypParser->yyerrcnt--;
	  yymajor = YYNOCODE;
    }else if( yyact < YYNSTATE + YYNRULE ){
      yy_reduce(yypParser,yyact-YYNSTATE);
    }else{
#ifdef YYERRORSYMBOL
      int yymx;
#endif
      assert( yyact == YY_ERROR_ACTION );
#ifndef NDEBUG
      if( yyTraceFILE ){
        fprintf(yyTraceFILE,"%sSyntax Error!\n",yyTracePrompt);
      }
#endif
#ifdef YYERRORSYMBOL
      /* A syntax error has occurred.
      ** The response to an error depends upon whether or not the
      ** grammar defines an error token "ERROR".
      **
      ** This is what we do if the grammar does define ERROR:
      **
      **  * Call the %syntax_error function.
      **
      **  * Begin popping the stack until we enter a state where
      **    it is legal to shift the error symbol, then shift
      **    the error symbol.
      **
      **  * Set the error count to three.
      **
      **  * Begin accepting and shifting new tokens.  No new error
      **    processing will occur until three tokens have been
      **    shifted successfully.
      **
      */
      if( yypParser->yyerrcnt<0 ){
        yy_syntax_error(yypParser,yymajor,yyminorunion);
      }
      yymx = yypParser->yystack[yypParser->yyidx].major;
      if( yymx==YYERRORSYMBOL || yyerrorhit ){
#ifndef NDEBUG
        if( yyTraceFILE ){
          fprintf(yyTraceFILE,"%sDiscard input token %s\n",
             yyTracePrompt,yyTokenName[yymajor]);
        }
#endif
        yy_destructor((YYCODETYPE)yymajor,&yyminorunion);
        yymajor = YYNOCODE;
      }else{
         while(
          yypParser->yyidx >= 0 &&
          yymx != YYERRORSYMBOL &&
          (yyact = yy_find_reduce_action(
                        yypParser->yystack[yypParser->yyidx].stateno,
                        YYERRORSYMBOL)) >= YYNSTATE
		  ){
          yy_pop_parser_stack(yypParser);
        }
        if( yypParser->yyidx < 0 || yymajor==0 ){
          yy_destructor((YYCODETYPE)yymajor,&yyminorunion);
          yy_parse_failed(yypParser);
          yymajor = YYNOCODE;
        }else if( yymx!=YYERRORSYMBOL ){
          YYMINORTYPE u2;
          u2.YYERRSYMDT = 0;
          yy_shift(yypParser,yyact,YYERRORSYMBOL,&u2);
        }
      }
      yypParser->yyerrcnt = 3;
      yyerrorhit = 1;
#else  /* YYERRORSYMBOL is not defined */
      /* This is what we do if the grammar does not define ERROR:
      **
      **  * Report an error message, and throw away the input token.
      **
      **  * If the input token is $, then fail the parse.
      **
      ** As before, subsequent error messages are suppressed until
      ** three input tokens have been successfully shifted.
      */
      if( yypParser->yyerrcnt<=0 ){
        yy_syntax_error(yypParser,yymajor,yyminorunion);
      }
      yypParser->yyerrcnt = 3;
      yy_destructor((YYCODETYPE)yymajor,&yyminorunion);
      if( yyendofinput ){
        yy_parse_failed(yypParser);
      }
      yymajor = YYNOCODE;
#endif
    }
  }while( yymajor!=YYNOCODE && yypParser->yyidx>=0 );
  return;
}
