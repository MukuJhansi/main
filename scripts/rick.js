document.addEventListener('DOMContentLoaded', (event) => {
    const video = document.getElementById('myVideo');
    video.play();
    video.requestFullscreen().catch(err => {
        console.log(`Error attempting to enable full-screen mode: ${err.message} (${err.name})`);
    });
});