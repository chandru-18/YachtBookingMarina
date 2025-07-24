// This ensures the DOM is fully loaded before running the script
document.addEventListener('DOMContentLoaded', () => {

    // --- Global Script Logic (e.g., for flash messages) ---
    const messages = document.querySelectorAll('.message');
    messages.forEach(message => {
        setTimeout(() => {
            message.style.display = 'none';
        }, 5000); // Hide after 5 seconds
    });

    // --- Booking Page Specific Logic ---
    const bookingForm = document.getElementById('booking-form');

    if (bookingForm) {
        console.log("Booking form found. Initializing script..."); // Debug log

        const startTimeInput = document.getElementById('startTime');
        const endTimeInput = document.getElementById('endTime');
        const totalPriceDisplay = document.getElementById('total-price-display');
        const numberOfPersonsInput = document.getElementById('numberOfPersons');
        const bookingDateInput = document.getElementById('bookingDate');

        // Get the boat data from the data-attributes of the form container
        const formContainer = document.querySelector('.form-container');

        // IMPORTANT: Add checks here
        if (!formContainer) {
            console.error("Error: .form-container not found!");
            return; // Exit if the container isn't found
        }

        const boatPricePerHour = parseFloat(formContainer.dataset.boatPricePerHour);
        const boatMaxPersons = parseInt(formContainer.dataset.boatMaxPersons);

        console.log("boatPricePerHour from data-attribute:", boatPricePerHour); // Debug log
        console.log("boatMaxPersons from data-attribute:", boatMaxPersons);     // Debug log

        function calculateTotalPrice() {
            console.log("calculateTotalPrice function called."); // Debug log
            const startTime = startTimeInput.value;
            const endTime = endTimeInput.value;

            console.log("Selected Start Time:", startTime); // Debug log
            console.log("Selected End Time:", endTime);     // Debug log

            if (startTime && endTime) {
                const [startHour, startMinute] = startTime.split(':').map(Number);
                const [endHour, endMinute] = endTime.split(':').map(Number);

                const startTotalMinutes = startHour * 60 + startMinute;
                const endTotalMinutes = endHour * 60 + endMinute;

                console.log("Start Total Minutes:", startTotalMinutes); // Debug log
                console.log("End Total Minutes:", endTotalMinutes);     // Debug log


                if (endTotalMinutes <= startTotalMinutes) {
                    totalPriceDisplay.textContent = 'Invalid Time';
                    console.warn("End time is not after start time."); // Debug log
                    return;
                }

                const durationMinutes = endTotalMinutes - startTotalMinutes;
                const durationHours = durationMinutes / 60;

                console.log("Duration Hours:", durationHours); // Debug log

                // Basic validation for price calculation
                if (isNaN(boatPricePerHour) || isNaN(durationHours) || durationHours <= 0) { // Added durationHours <= 0 check
                    totalPriceDisplay.textContent = 'AED Invalid Calculation';
                    console.error("Calculation resulted in NaN or invalid duration. boatPricePerHour:", boatPricePerHour, "durationHours:", durationHours); // Debug log
                    return;
                }

                const price = durationHours * boatPricePerHour;
                totalPriceDisplay.textContent = `AED ${price.toFixed(2)}`; // Format to 2 decimal places
                console.log("Calculated Price:", price); // Debug log
            } else {
                totalPriceDisplay.textContent = 'AED 0';
                console.log("Times not fully selected."); // Debug log
            }
        }

        // Set max persons attribute dynamically
        if (numberOfPersonsInput) {
            numberOfPersonsInput.setAttribute('max', boatMaxPersons);
        }

        // Attach event listeners to recalculate price whenever times change
        startTimeInput.addEventListener('change', calculateTotalPrice);
        endTimeInput.addEventListener('change', calculateTotalPrice);
        console.log("Event listeners attached to startTime and endTime inputs."); // Debug log

        // Initial calculation (in case the form fields are pre-populated, though usually not for new bookings)
        calculateTotalPrice();

        // Set min date for bookingDate input
        if (bookingDateInput) {
            const today = new Date();
            const year = today.getFullYear();
            const month = String(today.getMonth() + 1).padStart(2, '0'); // Month is 0-indexed
            const day = String(today.getDate()).padStart(2, '0');
            const minDate = `${year}-${month}-${day}`;
            bookingDateInput.setAttribute('min', minDate);
        }

        // Set min/max time for start/end time inputs (for UX)
        startTimeInput.setAttribute('min', '09:00');
        startTimeInput.setAttribute('max', '21:00');
        endTimeInput.setAttribute('min', '09:00');
        endTimeInput.setAttribute('max', '21:00');
    } else {
        console.log("Not on the booking page. Skipping booking-specific script initialization."); // Debug log
    }
});