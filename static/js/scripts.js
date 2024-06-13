document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
        e.preventDefault();

        document.querySelector(this.getAttribute('href')).scrollIntoView({
            behavior: 'smooth'
        });
    });
});

flatpickr("#appointment-date", {
    enableTime: true,
    dateFormat: "Y-m-d H:i",
     minDate: "tomorrow",
    locale: "ru", // Set Russian locale
});

const appointmentDateInput = document.getElementById("appointment-date");
const errorMessage = document.getElementById("error-message");

flatpickr(appointmentDateInput, {
      enableTime: true,
      dateFormat: "Y-m-d H:i",
      minDate: "tomorrow",
      locale: "ru", // Set Russian locale
      onChange: function(selectedDates, dateStr, instance) {
          const selectedDate = selectedDates[0];
          const tomorrow = new Date();
          tomorrow.setDate(tomorrow.getDate() + 1);
          tomorrow.setHours(0, 0, 0, 0);

          if (selectedDate < tomorrow) {
              errorMessage.style.display = "block";
              appointmentDateInput.value = ""; // Clear the input value
          } else {
              errorMessage.style.display = "none";
          }
      }
});