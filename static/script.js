// // jason :
// var msg = new SpeechSynthesisUtterance(document.getElementById("sidenavbar").innerHTML);
// window.SpeechSynthesisUtterance.speak(msg);
// speechSynthesis.getVoices().forEach(function(voice) {
//   console.log(voice.name, voice.default ? voice.default :'');
// });



var nav_color = document.getElementById("sidenavbar");
var nav_items = document.getElementsByClassName("nav-item nav-link");
// var reg_button = document.getElementById("reg_button");
var login_button = document.getElementById("login_button");

var default_button = document.getElementById("default-mode-button");
var dark_button = document.getElementById("dark-mode-button");
var light_button = document.getElementById("light-mode-button");
var forum_containers = document.getElementsByClassName("forum-content-container");
var forum_headers = document.getElementsByClassName("forum_header");
var create_new_post = document.getElementsByClassName("new-post-button");
var cards = document.getElementsByClassName("card");
var cards_content = document.getElementsByClassName("card-username");
var cards_title = document.getElementsByClassName("text-muted");


function darkMode(elem){
    light_button.style["box-shadow"] = "none";
    elem.style["box-shadow"] = "2px 8px 45px rgba(255, 255, 255, 1)";

    default_button.style["box-shadow"] = "none";

    nav_color.style["background-color"] = "black";
    for(var i = 0; i < nav_items.length; i++){ nav_items[i].style["color"] = "white";}
    for(var i = 0; i < forum_containers.length; i++){ forum_containers[i].style["background-color"] = "#121212";}
    // document.getElementById("test123").style["color"] = "blue";
    for(var i = 0; i < forum_headers.length; i++){ forum_headers[i].style["color"] = "#BB86FC";}
    document.getElementById("class-text").style["color"] = "#BB86FC";
    for(var i = 0; i < create_new_post.length; i++){ create_new_post[i].style["background-color"] = "#BB86FC";}

    for(var i = 0; i < cards.length; i++){
        cards[i].style["border"] = "none";
        cards[i].style["background"] = "grey";
        cards[i].style["color"] = "rgba(238, 238, 238, 1)";
        cards_content[i].style["color"] = "#352b2d";
        cards_title[i].style["color"] = "white";

    }

    for(var i = 0; i < cards_content.length; i++){
        // cards_content[i].style["color"] = "rgba(47, 47, 47, 1)";
    }
    reg_button.style["color"] = "black";
    document.getElementById("login_button").style["color"] = "black";


}
function defaultMode(elem){
    light_button.style["box-shadow"] = "none";
    elem.style["box-shadow"] = "2px 8px 45px rgba(255, 255, 255, 1)";

    dark_button.style["box-shadow"] = "none";

    nav_color.style["background-color"] = "#330000";
    for(var i = 0; i < nav_items.length; i++){ nav_items[i].style["color"] = "#818181";}
    for(var i = 0; i < forum_containers.length; i++){ forum_containers[i].style["background-color"] = "rgb(240, 240, 240)";}
    for(var i = 0; i < forum_headers.length; i++){ forum_headers[i].style["color"] = "rgb(73, 73, 73)";}
    document.getElementById("class-text").style["color"] = "rgb(73, 73, 73)";
    for(var i = 0; i < create_new_post.length; i++){ create_new_post[i].style["background-color"] = "#330000";}

    for(var i = 0; i < cards.length; i++){
        cards[i].style["border"] = "none";
        cards[i].style["background"] = "white";
        cards[i].style["color"] = "black";
    }

    for(var i = 0; i < cards_content.length; i++){
        cards_content[i].style["color"] = "black";
    }

    reg_button.style["color"] = "#818181";
    login_button.style["color"] = "#818181";

}
function lightMode(elem){
    elem.style["box-shadow"] = "2px 8px 45px grey";
    default_button.style["box-shadow"] = "none";
    dark_button.style["box-shadow"] = "none";

    nav_color.style["background-color"] = "rgb(238, 235, 235)";
    for(var i = 0; i < nav_items.length; i++){ nav_items[i].style["color"] = "#121212";}
    for(var i = 0; i < forum_containers.length; i++){ forum_containers[i].style["background-color"] = "white";}
    for(var i = 0; i < forum_headers.length; i++){ forum_headers[i].style["color"] = "black";}
    document.getElementById("class-text").style["color"] = "black";
    for(var i = 0; i < create_new_post.length; i++){ create_new_post[i].style["background-color"] = "#121212";}

    for(var i = 0; i < cards.length; i++){
        cards[i].style["border"] = "3px solid black";
        cards[i].style["background"] = "white";
        cards[i].style["color"] = "black";
    }

    for(var i = 0; i < cards_content.length; i++){
        cards_content[i].style["color"] = "black";
    }

    reg_button.style["color"] = "black";
    login_button.style["color"] = "black";

}
