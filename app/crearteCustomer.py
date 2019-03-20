import simplify
 
simplify.public_key = "sbpb_Njc3ZDkyMmYtYTE0OS00MTRjLWE5YmUtZjQ3MTI5ZWUzNmE3"
simplify.private_key = "3KzZq8dCCUhQMh1dTCU6jPrwdG0O4wwwizAP82LcfpN5YFFQL0ODSXAOkNtXTToq"
 
customer = simplify.Customer.create({
        "email" : "customer@mastercard.com",
        "name" : "Customer Customer",
        "card" : {
           "expMonth" : "11",
           "expYear" : "19",
           "cvc" : "123",
           "number" : "5555555555554444"
        },
        "reference" : "Ref1"
 
})
 
print customer