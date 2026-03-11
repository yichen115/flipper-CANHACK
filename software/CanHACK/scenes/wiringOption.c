#include "../app_user.h"

void app_scene_wiring_on_enter(void* context) {
    App* app = context;
    
    // Reset and configure text box
    text_box_reset(app->textBox);
    text_box_set_font(app->textBox, TextBoxFontText);
    text_box_set_focus(app->textBox, TextBoxFocusStart);

    // Wiring diagram text
    const char* wiring_text = 
        "Wiring Diagram\n"
        "===============\n\n"
        "Flipper    MCP2515\n"
        "--------------\n"
        "Pin 1  ->  VCC\n"
        "Pin 2  ->  SI\n"
        "Pin 3  ->  SO\n"
        "Pin 4  ->  CS\n"
        "Pin 5  ->  SCK\n"
        "Pin 6  ->  INT\n"
        "Pin 11 ->  GND\n\n";

    text_box_set_text(app->textBox, wiring_text);

    view_dispatcher_switch_to_view(app->view_dispatcher, TextBoxView);
}

bool app_scene_wiring_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

void app_scene_wiring_on_exit(void* context) {
    App* app = context;
    text_box_reset(app->textBox);
}
