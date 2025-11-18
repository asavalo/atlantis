#include <stdio.h>

int test_function() {
    int choice, a, b;

    printf("Enter an operation code (1-4):\n");
    printf("1: Add\n2: Subtract\n3: Multiply\n4: Divide\n");
    scanf("%d", &choice);

    printf("Enter two integers:\n");
    scanf("%d %d", &a, &b);

    switch (choice) {
        case 1:
            printf("Result: %d\n", a + b);
            break;
        case 2:
            printf("Result: %d\n", a - b);
            break;
        case 3:
            printf("Result: %d\n", a * b);
            break;
        case 4:
            if (b != 0)
                printf("Result: %d\n", a / b);
            else
                printf("Error: Division by zero\n");
            break;
        default:
            printf("Invalid operation code.\n");
            break;
    }

    return 0;
}
