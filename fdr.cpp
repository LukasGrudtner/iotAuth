#include "fdr.h"
#include <iostream>

/*  getOperator()
    Retorna o atributo 'operador' do objeto.
*/
char FDR::getOperator()
{
    return _operator;
}

/*  getOperand()
    Retorna o atributo 'operando' do objeto.
*/
int FDR::getOperand()
{
    return _operand;
}

/*  setOperator()
    Seta o atributo 'operador' do objeto com o valor recebido por parâmetro.
*/
void FDR::setOperator(char op)
{
    _operator = op;
}

/*  setOperand()
    Seta o atributo 'operando' do objeto com o valor recebido por parâmetro.
*/
void FDR::setOperand(int operand)
{
    _operand = operand;
}

/*  toString()
    Retorna uma representação da FDR em formato String.
*/
std::string FDR::toString()
{
    std::string result = _operator + std::to_string(_operand);
    return result;
}
