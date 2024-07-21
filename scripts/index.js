document.addEventListener('DOMContentLoaded', function () {
    let currentSlide = 0;
    const slides = document.querySelectorAll('.slider-image');
    const dots = document.querySelectorAll('.dot');

    function showSlide(index) {
        slides.forEach((slide, i) => {
            slide.classList.remove('active');
            dots[i].classList.remove('active-dot');
        });

        slides[index].classList.add('active');
        dots[index].classList.add('active-dot');
    }

    function nextSlide() {
        currentSlide = (currentSlide + 1) % slides.length;
        showSlide(currentSlide);
    }

    function prevSlide() {
        currentSlide = (currentSlide - 1 + slides.length) % slides.length;
        showSlide(currentSlide);
    }

    function initSlider() {
        dots.forEach((dot, index) => {
            dot.addEventListener('click', function () {
                currentSlide = index;
                showSlide(currentSlide);
            });
        });

        document.querySelector('.next-btn').addEventListener('click', nextSlide);
        document.querySelector('.prev-btn').addEventListener('click', prevSlide);

        setInterval(nextSlide, 5000); // Change slide every 5 seconds
    }

    initSlider();
});
