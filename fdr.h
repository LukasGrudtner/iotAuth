#ifndef FDR_H
#define FDR_H

#include <string>

class FDR
{
    public:
        char getOperator();
        int getOperand();
        void setOperator(char op);
        void setOperand(int operand);

        std::string toString();

    private:
        char _operator = '+';
        int _operand = 0;
};

#endif
