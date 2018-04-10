#include "fdr.h"

FDR::FDR(){}

FDR::FDR(char op, int operand)
{
    _operator = op;
    _operand = operand;
}

char FDR::getOperator()
{
    return _operator;
}

int FDR::getOperand()
{
    return _operand;
}

void FDR::setOperator(char op)
{
    _operator = op;
}

void FDR::setOperand(int operand)
{
    _operand = operand;
}
