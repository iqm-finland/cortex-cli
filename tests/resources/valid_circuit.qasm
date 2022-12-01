OPENQASM 2.0;
include "qelib1.inc";
qreg q[2];
creg b[2];
x q[0];
cz q[0], q[1];
measure q -> b;