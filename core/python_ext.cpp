#include <Python.h>
#include <structmember.h>
#include "InstManager.h"

using namespace devmp;

static PyObject *method_version(PyObject * self, PyObject * args) {
    return PyUnicode_FromString("v1.0");
}

static PyMethodDef module_methods[] = {
        {"version", method_version, METH_VARARGS, "Get Version"},
        {nullptr,   nullptr, 0,                   nullptr}
};

static struct PyModuleDef asm_module = {
        PyModuleDef_HEAD_INIT,
        "pydevmp",
        "A library to remove useless assembly instruction",
        -1,
        module_methods
};

typedef struct {
    PyObject_HEAD
    InstManager obj;
} PyInstManager;

static int PyInstManager_init(PyInstManager *self, PyObject *args) {
    if (!PyArg_ParseTuple(args, ":")) return -1;
    new(&self->obj) InstManager;
    return 0;
}

static PyObject *PyInstManager_next(PyInstManager *self, PyObject *args) {
    if (!PyArg_ParseTuple(args, ":"))
        return nullptr;
    if (self->obj.next()) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}

static PyObject *PyInstManager_bytes(PyInstManager *self, PyObject *args) {
    if (!PyArg_ParseTuple(args, ":"))
        return nullptr;
    uint8_t * ptr;
    size_t size;
    self->obj.getBytes(ptr,size);
    PyObject * result= PyBytes_FromStringAndSize((const char *)(ptr), (Py_ssize_t)size);
    delete [] ptr;
    return result;
}

static PyObject *PyInstManager_setAsm(PyInstManager *self, PyObject *args) {
    Py_buffer asm_;
    unsigned long long address = 0;
    if (!PyArg_ParseTuple(args, "y*|K:", &asm_, &address))
        return nullptr;
    return PyLong_FromLongLong(self->obj.setAsm((unsigned char *) asm_.buf, asm_.len, address));
}

static PyObject *PyInstManager_str(PyInstManager *self) {
    std::string s = self->obj.toString();
    return PyUnicode_FromStringAndSize(s.c_str(), (Py_ssize_t) s.size());
}

static PyObject *PyInstManager_clear(PyInstManager *self, PyObject *args) {
    if (!PyArg_ParseTuple(args, ":"))
        return nullptr;
    self->obj.clear();
    Py_RETURN_NONE;
}
static PyObject *PyInstManager_setUseless(PyInstManager *self, PyObject *args) {
    int flag = 1;
    if (!PyArg_ParseTuple(args, "|p:", &flag))
        return nullptr;
    self->obj.insts->back()->setUseless(flag!=0);
    Py_RETURN_NONE;
}
static PyObject *PyInstManager_setKeep(PyInstManager *self, PyObject *args) {
    int flag = 1;
    if (!PyArg_ParseTuple(args, "|p:", &flag))
        return nullptr;
    self->obj.insts->back()->setKeep(flag!=0);
    Py_RETURN_NONE;
}

static PyObject *PyInstManager_getDeletedAddr(PyInstManager *self, PyObject *args) {
    if (!PyArg_ParseTuple(args, ":"))
        return nullptr;
    auto r=self->obj.getDeletedAddr();
    PyObject*result=PyList_New(r.size());
    size_t idx=0;
    for(size_t i:r){
        PyList_SetItem(result, idx++, PyLong_FromLongLong(i));
    }
    return result;
}


static PyObject *PyInstManager_getUsefulAddr(PyInstManager *self, PyObject *args) {
    if (!PyArg_ParseTuple(args, ":"))
        return nullptr;
    auto r=self->obj.getUsefulAddr();
    PyObject*result=PyList_New(r.size());
    size_t idx=0;
    for(size_t i:r){
        PyList_SetItem(result, idx++, PyLong_FromLongLong(i));
    }
    return result;
}

static PyMethodDef PyInstManager_methods[] = {
        {"next",     (PyCFunction) PyInstManager_next,     METH_VARARGS, "Run next instruction"},
        {"__bytes__", (PyCFunction) PyInstManager_bytes, METH_VARARGS, "Get assembly bytes"},
        {"dump", (PyCFunction) PyInstManager_bytes, METH_VARARGS, "Get assembly bytes"},
        {"setAsm",   (PyCFunction) PyInstManager_setAsm,   METH_VARARGS, "Set assembly"},
        {"clear",    (PyCFunction) PyInstManager_clear,    METH_VARARGS, "Clear"},
        {"setUseless",    (PyCFunction) PyInstManager_setUseless,    METH_VARARGS, "Set the last instruction is useless"},
        {"setKeep",    (PyCFunction) PyInstManager_setKeep,    METH_VARARGS, "Keep the last instruction"},
        {"getDeletedAddr",    (PyCFunction) PyInstManager_getDeletedAddr,    METH_VARARGS, "Get deleted instructions"},
        {"getUsefulAddr",    (PyCFunction) PyInstManager_getUsefulAddr,    METH_VARARGS, "Get useful instructions"},
        {nullptr,    nullptr, 0,                                         nullptr}
};

static PyGetSetDef PyInstManager_getset[] = {
        {"remained_assembly_count", [](PyObject *self, void *) {
            auto s = (PyInstManager*)self;
            return PyLong_FromSize_t(s->obj.insn_count - s->obj.insn_index);
        }, nullptr, "The number of remained instructions"},
        {"inst_count", [](PyObject *self, void *) {
            auto s = (PyInstManager*)self;
            return PyLong_FromSize_t(s->obj.insts->size());
        }, nullptr, "The number of processed instructions"},
        {nullptr, nullptr, nullptr, nullptr, nullptr}
};

static PyTypeObject PyInstManager_Type = {
        .ob_base=PyObject_HEAD_INIT(nullptr)
        .tp_name="pydevmp.InstManager",
        .tp_basicsize= sizeof(PyInstManager),
        .tp_dealloc=[](PyObject *self) {
            PyObject_GC_UnTrack(self);
            PyObject_GC_Del(self);
        },
        .tp_str=(reprfunc) PyInstManager_str,
        .tp_flags=Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,
        .tp_doc="Instruction Manager",
        .tp_traverse=[](PyObject *self, visitproc visit, void *arg) { return 0; },
        .tp_methods=PyInstManager_methods,
        .tp_getset=PyInstManager_getset,
        .tp_init=(initproc) PyInstManager_init,
        .tp_new=[](PyTypeObject *type, PyObject *args, PyObject *kwds) { return PyObject_GC_New(PyObject, type); },
        .tp_finalize=[](PyObject *self) { ((PyInstManager *) self)->obj.~InstManager(); },
};

PyMODINIT_FUNC PyInit_pydevmp(void) {
    if (PyType_Ready(&PyInstManager_Type) < 0)
        return nullptr;

    PyObject * module = PyModule_Create(&asm_module);
    Py_INCREF(&PyInstManager_Type);
    PyModule_AddObject(module, "InstManager", (PyObject *) &PyInstManager_Type);

    return module;
}
