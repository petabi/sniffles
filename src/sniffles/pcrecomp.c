#include <Python.h>
#include <stdbool.h>
#include <stdint.h>

#include "pcre.h"
#include "pcre_internal.h"

static PyObject *pcrecomp_compile(PyObject *, PyObject *);

struct realpcre {
  uint32_t magic_number;
  uint32_t size;               /* Total that was malloced */
  uint32_t options;            /* Public options */
  uint32_t flags;              /* Private flags */
  uint32_t limit_match;        /* Limit set from regex */
  uint32_t limit_recursion;    /* Limit set from regex */
  uint16_t first_char;         /* Starting character */
  uint16_t req_char;           /* This character must be seen */
  uint16_t max_lookbehind;     /* Longest lookbehind (characters) */
  uint16_t top_bracket;        /* Highest numbered group */
  uint16_t top_backref;        /* Highest numbered back reference */
  uint16_t name_table_offset;  /* Offset to name table that follows */
  uint16_t name_entry_size;    /* Size of any name items */
  uint16_t name_count;         /* Number of name items */
  uint16_t ref_count;          /* Reference count */
};

static PyMethodDef PcreCompMethods[] = {
  {"compile", pcrecomp_compile, METH_VARARGS,
   "Compile a regular expression."},
  {NULL, NULL, 0, NULL}
};

static struct PyModuleDef pcrecompmodule = {
  PyModuleDef_HEAD_INIT,
  "pcrecomp",
  NULL,
  -1,
  PcreCompMethods
};

static PyObject *PCREError;

PyMODINIT_FUNC PyInit_pcrecomp(void)
{
  PyObject *m = PyModule_Create(&pcrecompmodule);
  if (m == NULL) return NULL;
  PyModule_AddIntConstant(m, "PCRE_MAJOR", PCRE_MAJOR);
  PyModule_AddIntConstant(m, "PCRE_MINOR", PCRE_MINOR);
  PCREError = PyErr_NewException("pcrecomp.PCREError", NULL, NULL);
  Py_INCREF(PCREError);
  PyModule_AddObject(m, "PCREError", PCREError);
  return m;
}

static PyObject *pcrecomp_compile(PyObject *self, PyObject *args)
{
  const char *pattern = NULL;
  int options = 0;
  if (PyArg_ParseTuple(args, "s|i", &pattern, &options) != true)
    return NULL;

  const char *error;
  int erroffset;
  struct realpcre *re =
      (struct realpcre *)pcre_compile(pattern, options,
                                      &error, &erroffset, NULL);
  if (!re) {
    PyErr_SetString(PCREError, error);
    return NULL;
  }

  int offset = re->name_table_offset;
  int count = re->name_count;
  int size = re->name_entry_size;
  if (re->magic_number != 0x50435245UL) {
    offset = ((offset << 8) & 0xff00) | ((offset >> 8) & 0xff);
    count = ((count << 8) & 0xff00) | ((count >> 8) & 0xff);
    size = ((size << 8) & 0xff00) | ((size >> 8) & 0xff);
  }
  int rebin_offset = offset + count * size;
  const char *codestart = (const char *)re + rebin_offset;
  if (*(unsigned char *)codestart != OP_BRA) {
    pcre_free(re);
    PyErr_SetString(PCREError, "Incompatible PCRE library.");
    return NULL;
  }
  int codesize = re->size - rebin_offset;
  PyObject *rebin = PyBytes_FromStringAndSize(codestart, codesize);
  return rebin;
}
