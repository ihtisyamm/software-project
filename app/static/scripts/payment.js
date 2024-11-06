console.log("Payment.js is loaded");

fetch("/config")
    .then((result) => {
        return result.json();})
    .then((data) => {
        const stripe = Stripe(data.publicKey);

        const buttons = Array.from(document.querySelectorAll("button[stripe-button]"));

        buttons.forEach((button) => {
            button.addEventListener("click", (event) => {
                const buttonId = event.target.id;
                const baseURL = "/create-checkout-session/"
                const finalURL = baseURL.concat(buttonId);

                fetch(finalURL)
                    .then((result) => { return result.json(); })
                    .then((data) => {
                        console.log(data);
                        return stripe.redirectToCheckout({"sessionId": data.sessionId})
                    })
                    .then((res) => {
                        console.log(res);
                    });
            });
        });
    });